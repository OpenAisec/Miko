# Koa Security Audit Guide

> Koa.js Framework 安全审计模块
> 适用于: Koa 2.x, Koa-Router, Koa-Body

## 核心危险面

Koa 作为 Express 的精简继任者,采用中间件级联架构和 async/await 语法。主要安全风险：中间件顺序错误、请求体解析漏洞、不当的错误处理、原型污染、路径遍历、NoSQL注入等。

---

## 中间件顺序和安全配置

```javascript
// 危险配置 - 中间件顺序错误
const app = new Koa();

app.use(router.routes());        // ❌ 路由在安全中间件之前
app.use(helmet());                // ❌ 太晚了

// 正确顺序
const app = new Koa();

// 1. 错误处理 (最外层)
app.use(async (ctx, next) => {
    try {
        await next();
    } catch (err) {
        ctx.status = err.status || 500;
        ctx.body = { error: 'Internal Server Error' };  // ✓ 不泄露详情
        ctx.app.emit('error', err, ctx);
    }
});

// 2. 安全头
app.use(helmet());  // ✓

// 3. CORS
app.use(cors({
    origin: 'https://app.example.com',  // ✓ 具体域名
    credentials: true
}));

// 4. 请求体解析
app.use(bodyParser({
    jsonLimit: '1mb',  // ✓ 限制大小
    formLimit: '1mb'
}));

// 5. 身份验证
app.use(auth());

// 6. 路由 (最后)
app.use(router.routes());
app.use(router.allowedMethods());
```

---

## 请求体解析和原型污染

```javascript
// 危险配置 - koa-body / koa-bodyparser
app.use(bodyParser());  // ❌ 默认配置可能不安全

// 审计检查
- jsonLimit / formLimit 配置
- 是否过滤 __proto__
- 是否验证 Content-Type

// 原型污染示例
app.use(bodyParser());

app.post('/api/update', async (ctx) => {
    const data = ctx.request.body;
    Object.assign(config, data);  // ❌ High: 原型污染
    ctx.body = { success: true };
});

// 攻击载荷
POST /api/update
Content-Type: application/json

{
  "__proto__": {
    "isAdmin": true,
    "role": "admin"
  }
}

// 安全修复
app.use(bodyParser({
    jsonLimit: '1mb',
    formLimit: '1mb',
    textLimit: '1mb',
    enableTypes: ['json', 'form'],  // ✓ 明确类型
    extendTypes: {
        json: ['application/json']
    }
}));

app.post('/api/update', async (ctx) => {
    const data = ctx.request.body;

    // 1. 过滤危险键
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key of dangerousKeys) {
        if (key in data) {
            ctx.throw(400, 'Invalid key');
        }
    }

    // 2. 使用白名单
    const allowedKeys = ['name', 'email', 'bio'];
    const safeData = {};
    for (const key of allowedKeys) {
        if (data.hasOwnProperty(key)) {
            safeData[key] = data[key];
        }
    }

    Object.assign(config, safeData);  // ✓
    ctx.body = { success: true };
});
```

---

## NoSQL 注入检测 (MongoDB)

```javascript
// 危险操作
app.get('/user', async (ctx) => {
    const filter = ctx.query;
    const user = await User.findOne(filter);  // ❌ High: NoSQL注入
    ctx.body = user;
});

// 攻击载荷
GET /user?username[$ne]=null&password[$ne]=null  // 绕过认证
GET /user?$where=this.password.length<20         // $where注入

// 审计正则
findOne\(ctx\.(query|request\.body)\)|find\(ctx\.(query|request\.body)\)
\$where|\$regex

// 安全修复
app.get('/user', async (ctx) => {
    const { username } = ctx.query;

    // 1. 类型验证
    if (typeof username !== 'string') {
        ctx.throw(400, 'Invalid username type');
    }

    // 2. 禁止操作符
    if (username.startsWith('$')) {
        ctx.throw(400, 'Invalid username');
    }

    // 3. 明确字段
    const user = await User.findOne({ username: username });  // ✓

    ctx.body = user;
});

// 高级防护 - 递归清理
function sanitizeQuery(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    for (const key in obj) {
        // 删除操作符键
        if (key.startsWith('$')) {
            delete obj[key];
            continue;
        }

        // 递归清理
        if (typeof obj[key] === 'object') {
            obj[key] = sanitizeQuery(obj[key]);
        }
    }

    return obj;
}

app.use(async (ctx, next) => {
    ctx.query = sanitizeQuery(ctx.query);  // ✓ 全局清理
    if (ctx.request.body) {
        ctx.request.body = sanitizeQuery(ctx.request.body);
    }
    await next();
});
```

---

## SSRF 检测

```javascript
// 危险操作
const axios = require('axios');

app.get('/fetch', async (ctx) => {
    const url = ctx.query.url;
    const response = await axios.get(url);  // ❌ High: SSRF
    ctx.body = response.data;
});

// 攻击载荷
GET /fetch?url=http://169.254.169.254/latest/meta-data/
GET /fetch?url=http://localhost:6379/
GET /fetch?url=file:///etc/passwd

// 审计正则
axios\.(get|post).*ctx\.query|got\(ctx\.query|fetch\(ctx\.query

// 安全修复
const { URL } = require('url');
const dns = require('dns').promises;

app.get('/fetch', async (ctx) => {
    const urlString = ctx.query.url;

    try {
        const url = new URL(urlString);

        // 1. 协议白名单
        if (!['http:', 'https:'].includes(url.protocol)) {
            ctx.throw(403, 'Invalid protocol');
        }

        // 2. 主机白名单
        const allowedHosts = ['api.example.com', 'cdn.example.com'];
        if (!allowedHosts.includes(url.hostname)) {
            ctx.throw(403, 'Host not allowed');
        }

        // 3. DNS解析检查内网IP
        const addresses = await dns.resolve4(url.hostname);
        for (const addr of addresses) {
            if (isPrivateIP(addr)) {
                ctx.throw(403, 'Internal IP not allowed');
            }
        }

        // 4. 超时和大小限制
        const response = await axios.get(url.href, {
            timeout: 5000,
            maxContentLength: 1024 * 1024  // 1MB
        });

        ctx.body = response.data;
    } catch (err) {
        ctx.throw(400, 'Invalid request');
    }
});

// IP检查函数
function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    return (
        parts[0] === 10 ||
        parts[0] === 127 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168) ||
        parts[0] === 169 && parts[1] === 254
    );
}
```

---

## 路径遍历检测

```javascript
// 危险操作
const fs = require('fs').promises;
const path = require('path');

app.get('/download', async (ctx) => {
    const filename = ctx.query.file;
    const filePath = path.join(__dirname, 'files', filename);
    ctx.body = await fs.readFile(filePath);  // ❌ High: 路径遍历
});

// 攻击载荷
GET /download?file=../../etc/passwd
GET /download?file=..%2f..%2f..%2fetc%2fpasswd

// 审计正则
fs\.readFile.*ctx\.query|fs\.createReadStream.*ctx\.query
path\.join.*ctx\.(query|params)

// 安全修复
app.get('/download', async (ctx) => {
    const filename = ctx.query.file;

    // 1. 基本验证
    if (!filename || filename.includes('..') || filename.includes('/')) {
        ctx.throw(400, 'Invalid filename');
    }

    // 2. 扩展名白名单
    const ext = path.extname(filename).toLowerCase();
    const allowedExts = ['.pdf', '.jpg', '.png', '.txt'];
    if (!allowedExts.includes(ext)) {
        ctx.throw(403, 'File type not allowed');
    }

    // 3. 路径规范化和验证
    const baseDir = path.join(__dirname, 'files');
    const filePath = path.normalize(path.join(baseDir, filename));

    // 确保最终路径在 baseDir 内
    if (!filePath.startsWith(baseDir + path.sep)) {
        ctx.throw(403, 'Access denied');
    }

    // 4. 检查文件存在
    try {
        await fs.access(filePath, fs.constants.R_OK);
    } catch {
        ctx.throw(404, 'File not found');
    }

    // 5. 设置安全头
    ctx.set('Content-Disposition', `attachment; filename="${path.basename(filePath)}"`);
    ctx.set('X-Content-Type-Options', 'nosniff');

    ctx.body = await fs.readFile(filePath);  // ✓
});
```

---

## 命令注入检测

```javascript
// 危险操作
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

app.get('/ping', async (ctx) => {
    const host = ctx.query.host;
    const { stdout } = await execPromise(`ping -c 4 ${host}`);  // ❌ Critical
    ctx.body = stdout;
});

// 攻击载荷
GET /ping?host=google.com;whoami
GET /ping?host=`cat /etc/passwd`

// 审计正则
exec\(.*ctx\.|spawn\(.*ctx\.|execSync\(.*ctx\.

// 安全修复
const { execFile } = require('child_process');
const execFilePromise = util.promisify(execFile);

app.get('/ping', async (ctx) => {
    const host = ctx.query.host;

    // 1. 验证格式
    if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
        ctx.throw(400, 'Invalid hostname');
    }

    // 2. 使用 execFile (不启动shell)
    try {
        const { stdout } = await execFilePromise('ping', ['-c', '4', host], {
            timeout: 10000
        });  // ✓
        ctx.body = stdout;
    } catch (err) {
        ctx.throw(500, 'Ping failed');
    }
});

// 更安全: 避免命令执行，使用原生库
const ping = require('ping');

app.get('/ping', async (ctx) => {
    const host = ctx.query.host;
    const result = await ping.promise.probe(host);  // ✓ 纯JavaScript实现
    ctx.body = result;
});
```

---

## JWT 安全检测

```javascript
// 危险操作
const jwt = require('jsonwebtoken');

app.use(async (ctx, next) => {
    const token = ctx.headers.authorization;
    const decoded = jwt.decode(token);  // ❌ High: 未验证签名
    ctx.state.user = decoded;
    await next();
});

// 弱密钥
const SECRET = 'secret';  // ❌ Critical

// none 算法
jwt.sign(payload, null, { algorithm: 'none' });  // ❌ Critical

// 审计正则
jwt\.decode\((?!.*verify)|JWT_SECRET.*=.*['"][^'"]{1,16}|algorithm.*none

// 安全修复
app.use(async (ctx, next) => {
    const authHeader = ctx.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        ctx.throw(401, 'Missing token');
    }

    const token = authHeader.substring(7);

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256']  // ✓ 明确算法
        });
        ctx.state.user = decoded;
    } catch (err) {
        ctx.throw(401, 'Invalid token');
    }

    await next();
});

// 密钥管理
// .env
JWT_SECRET=at_least_32_bytes_random_string_here

// 生成强密钥
const crypto = require('crypto');
const secret = crypto.randomBytes(32).toString('hex');
```

---

## CORS 配置检测

```javascript
// 危险配置
const cors = require('@koa/cors');

app.use(cors({
    origin: '*',              // ❌ High: 允许所有域
    credentials: true         // ❌ 与 * 冲突
}));

// 审计正则
cors\(\{[^}]*origin:.*\*|credentials:\s*true

// 漏洞示例
app.use(cors({
    origin: ctx => ctx.headers.origin  // ❌ High: 反射Origin
}));

// 安全修复
// 方法1: 静态白名单
app.use(cors({
    origin: 'https://app.example.com',  // ✓
    credentials: true,
    allowMethods: ['GET', 'POST'],
    allowHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400
}));

// 方法2: 动态验证
const allowedOrigins = [
    'https://app.example.com',
    'https://admin.example.com'
];

app.use(cors({
    origin: (ctx) => {
        const origin = ctx.headers.origin;
        if (allowedOrigins.includes(origin)) {
            return origin;  // ✓
        }
        return false;  // 拒绝
    },
    credentials: true
}));

// 方法3: 子域名模式
app.use(cors({
    origin: (ctx) => {
        const origin = ctx.headers.origin;
        if (/^https:\/\/[a-z0-9-]+\.example\.com$/.test(origin)) {
            return origin;  // ✓ 允许子域名
        }
        return false;
    },
    credentials: true
}));
```

---

## 错误处理和信息泄露

```javascript
// 危险配置
app.on('error', (err, ctx) => {
    console.error(err.stack);  // ❌ 仅记录
});

// 默认错误处理
app.use(async (ctx) => {
    throw new Error('Database connection failed: user=admin, pass=secret123');
    // ❌ Medium: 错误可能泄露到客户端
});

// 审计正则
throw new Error.*password|console\.error.*stack|ctx\.body.*err\.stack

// 安全修复
// 全局错误处理中间件
app.use(async (ctx, next) => {
    try {
        await next();
    } catch (err) {
        ctx.status = err.status || err.statusCode || 500;

        // 后端记录完整错误
        console.error({
            error: err.message,
            stack: err.stack,
            url: ctx.url,
            method: ctx.method,
            ip: ctx.ip,
            user: ctx.state.user?.id
        });

        // 生产环境隐藏详情
        if (process.env.NODE_ENV === 'production') {
            ctx.body = {
                error: 'An error occurred',
                code: err.code || 'INTERNAL_ERROR'
            };  // ✓
        } else {
            ctx.body = {
                error: err.message,
                stack: err.stack  // 仅开发环境
            };
        }

        // 触发应用级错误事件
        ctx.app.emit('error', err, ctx);
    }
});

// 日志脱敏
const logger = require('pino')();

app.use(async (ctx, next) => {
    const sanitized = { ...ctx.request.body };
    delete sanitized.password;
    delete sanitized.token;
    logger.info({ body: sanitized }, 'Request received');  // ✓
    await next();
});
```

---

## CSRF 保护

```javascript
// Koa 没有内置 CSRF 保护，需要手动实现
const csrf = require('koa-csrf');

// 危险: 未启用 CSRF
app.use(router.routes());  // ❌ 状态改变操作无 CSRF 保护

// 安全配置
app.use(new csrf({
    invalidTokenMessage: 'Invalid CSRF token',
    invalidTokenStatusCode: 403,
    excludedMethods: ['GET', 'HEAD', 'OPTIONS'],  // ✓ 仅豁免安全方法
    disableQuery: false
}));

// 在表单中包含 CSRF token
app.use(async (ctx) => {
    await ctx.render('form', {
        csrfToken: ctx.csrf  // ✓
    });
});

// HTML
<form method="POST" action="/transfer">
    <input type="hidden" name="_csrf" value="{{ csrfToken }}">
    <input type="text" name="amount">
    <button type="submit">Transfer</button>
</form>

// AJAX 请求
axios.defaults.headers.common['X-CSRF-Token'] = csrfToken;
```

---

## 开放重定向检测

```javascript
// 危险操作
app.get('/redirect', async (ctx) => {
    const url = ctx.query.url;
    ctx.redirect(url);  // ❌ Medium: 开放重定向
});

// 攻击载荷
GET /redirect?url=https://evil.com/phishing

// 审计正则
ctx\.redirect\(ctx\.(query|request\.body)

// 安全修复
app.get('/redirect', async (ctx) => {
    const url = ctx.query.url;

    // 方法1: 白名单
    const allowedUrls = ['/home', '/dashboard', '/profile'];
    if (!allowedUrls.includes(url)) {
        ctx.redirect('/');  // 默认安全页面
        return;
    }

    // 方法2: 验证相对路径
    if (!url.startsWith('/') || url.startsWith('//')) {
        ctx.throw(400, 'Invalid redirect URL');
    }

    // 方法3: 验证域名
    try {
        const parsed = new URL(url, 'http://example.com');
        if (parsed.hostname !== 'example.com') {
            ctx.throw(403, 'External redirect not allowed');
        }
    } catch {
        ctx.throw(400, 'Invalid URL');
    }

    ctx.redirect(url);  // ✓
});
```

---

## 速率限制

```javascript
// 缺少速率限制
app.post('/login', async (ctx) => {
    // ❌ 无限制登录尝试
});

// 安全配置
const ratelimit = require('koa-ratelimit');
const Redis = require('ioredis');

const db = new Redis();

app.use(ratelimit({
    driver: 'redis',
    db: db,
    duration: 60000,  // 1分钟
    errorMessage: 'Too many requests',
    id: (ctx) => ctx.ip,
    headers: {
        remaining: 'Rate-Limit-Remaining',
        reset: 'Rate-Limit-Reset',
        total: 'Rate-Limit-Total'
    },
    max: 100,  // 每分钟100个请求
    disableHeader: false
}));

// 针对特定路由
const loginLimiter = ratelimit({
    driver: 'redis',
    db: db,
    duration: 60000,
    max: 5,  // 登录每分钟5次
    id: (ctx) => ctx.request.body.email || ctx.ip
});

router.post('/login', loginLimiter, async (ctx) => {
    // 登录逻辑
});
```

---

## 敏感信息和调试

```javascript
// 危险操作
app.use(async (ctx) => {
    console.log(ctx.request.body);  // ❌ 可能记录密码
    ctx.body = process.env;  // ❌ Critical: 环境变量泄露
});

// .env 泄露
DB_PASSWORD=secret123  // ❌ 如果代码泄露

// 审计正则
console\.log.*password|ctx\.body.*process\.env|DB_PASSWORD=

// 安全措施
// .gitignore
.env
.env.local
.env.*.local

// 环境变量验证
const requiredEnvVars = ['DB_PASSWORD', 'JWT_SECRET', 'SESSION_SECRET'];
for (const varName of requiredEnvVars) {
    if (!process.env[varName]) {
        throw new Error(`Missing required env var: ${varName}`);
    }
}

// 日志脱敏
const sanitizedBody = { ...ctx.request.body };
delete sanitizedBody.password;
delete sanitizedBody.creditCard;
logger.info({ body: sanitizedBody });  // ✓
```

---

## 搜索模式汇总

```regex
# 原型污染
Object\.assign.*ctx\.request\.body|_\.merge.*ctx\.request\.body

# NoSQL注入
findOne\(ctx\.query\)|find\(ctx\.request\.body\)

# SSRF
axios\.(get|post).*ctx\.query|fetch\(ctx\.query

# 路径遍历
fs\.readFile.*ctx\.query|createReadStream.*ctx\.query

# 命令注入
exec\(.*ctx\.|spawn\(.*ctx\.

# JWT
jwt\.decode\((?!.*verify)|algorithm.*none

# CORS
cors.*origin:.*\*

# 开放重定向
ctx\.redirect\(ctx\.query

# 敏感信息
console\.log.*password|ctx\.body.*process\.env
```

---

## 快速审计检查清单

```markdown
[ ] 检查 package.json 依赖漏洞 (npm audit)
[ ] 检查中间件顺序 (安全中间件应在前)
[ ] 搜索 Object.assign (原型污染)
[ ] 检查 findOne/find 的参数来源 (NoSQL注入)
[ ] 检查文件操作的路径拼接 (路径遍历)
[ ] 检查 HTTP 请求函数 (SSRF)
[ ] 检查 exec/spawn 命令执行
[ ] 检查 JWT 验证逻辑
[ ] 检查 CORS 配置
[ ] 检查错误处理是否泄露信息
[ ] 检查 CSRF 保护
[ ] 检查重定向目标验证
[ ] 检查登录/敏感接口的速率限制
[ ] 检查 .env 是否在 .gitignore
```

---

## 最小 PoC 示例
```bash
# 原型污染
node -e "const a={}; Object.assign(a, JSON.parse('{\"__proto__\":{\"polluted\":true}}')); console.log(({}).polluted)"

# SSRF
curl "http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/"

# 路径遍历
curl "http://localhost:3000/download?file=../../etc/passwd"
```

---

## 参考资源

- [Koa Official Documentation](https://koajs.com/)
- [Koa Security Best Practices](https://github.com/koajs/koa/wiki/Error-Handling)
- [Node.js Security Checklist](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
