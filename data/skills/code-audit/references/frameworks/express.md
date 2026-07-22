# Express.js Security Audit

> Express.js 框架安全审计模块
> 适用于: Express, Koa, Node.js 应用

## 识别特征

```javascript
// Express项目识别
const express = require('express');
const app = express();

// 文件结构
├── package.json
├── app.js / index.js
├── routes/
├── controllers/
├── models/
├── middleware/
└── views/
```

---

## Express特定漏洞

### 1. NoSQL注入 (MongoDB)

```javascript
// 危险: 直接使用用户输入
app.post('/login', async (req, res) => {
    const user = await User.findOne({
        username: req.body.username,
        password: req.body.password  // 可注入 {$gt: ""}
    });
});

// 攻击payload
// {"username": "admin", "password": {"$gt": ""}}

// 安全: 类型验证
app.post('/login', async (req, res) => {
    if (typeof req.body.username !== 'string' ||
        typeof req.body.password !== 'string') {
        return res.status(400).json({error: 'Invalid input'});
    }
    const user = await User.findOne({...});
});
```

### 2. 原型污染

```javascript
// 危险: 合并用户输入
const _ = require('lodash');
app.post('/config', (req, res) => {
    _.merge(config, req.body);  // 原型污染!
});

// 攻击payload
// {"__proto__": {"isAdmin": true}}

// 危险: 递归赋值
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key];  // 污染Object.prototype
    }
}

// 安全: 过滤危险键
const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];
function safeMerge(target, source) {
    for (let key in source) {
        if (FORBIDDEN_KEYS.includes(key)) continue;
        target[key] = source[key];
    }
}
```

### 3. 路径遍历

```javascript
// 危险: 用户输入拼接路径
app.get('/download', (req, res) => {
    const file = req.query.file;
    res.sendFile(`/uploads/${file}`);  // ../../etc/passwd
});

// 安全: 使用path.basename
const path = require('path');
app.get('/download', (req, res) => {
    const file = path.basename(req.query.file);  // 移除路径
    const fullPath = path.join('/uploads', file);
    // 验证在目标目录内
    if (!fullPath.startsWith('/uploads/')) {
        return res.status(400).send('Invalid path');
    }
    res.sendFile(fullPath);
});
```

### 4. 命令注入

```javascript
// 危险: exec拼接
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    exec(`ping -c 1 ${req.query.host}`, (err, stdout) => {  // RCE!
        res.send(stdout);
    });
});

// 安全: 使用execFile + 参数数组
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
    execFile('ping', ['-c', '1', req.query.host], (err, stdout) => {
        res.send(stdout);
    });
});
```

### 5. XSS (模板引擎)

```javascript
// EJS危险模式
<%- userInput %>  // 不转义

// 安全模式
<%= userInput %>  // 自动转义

// Pug/Jade危险模式
!{userInput}  // 不转义
p= userInput  // 安全

// Handlebars危险模式
{{{userInput}}}  // 三重大括号不转义
{{userInput}}    // 双重大括号安全
```

### 6. 会话安全

```javascript
// 危险: 不安全的session配置
app.use(session({
    secret: 'keyboard cat',  // 弱密钥
    cookie: { secure: false }  // 不安全
}));

// 安全配置
app.use(session({
    secret: process.env.SESSION_SECRET,
    name: 'sessionId',  // 更改默认名称
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 3600000
    },
    resave: false,
    saveUninitialized: false
}));
```

### 7. CORS配置

```javascript
// 危险: 允许所有来源
app.use(cors());
app.use(cors({ origin: '*' }));

// 危险: 反射Origin
app.use(cors({
    origin: (origin, callback) => {
        callback(null, origin);  // 反射任意来源
    },
    credentials: true  // 允许凭证更危险
}));

// 安全: 白名单
const allowedOrigins = ['https://trusted.com'];
app.use(cors({
    origin: (origin, callback) => {
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed'));
        }
    }
}));
```

### 8. 依赖安全

```bash
# 检查已知漏洞
npm audit
npm audit --json

# 检查过时依赖
npm outdated

# 检查package.json中的危险包
# - node-serialize (反序列化RCE)
# - js-yaml < 3.13.1 (代码执行)
# - lodash < 4.17.12 (原型污染)
```

### 9. 安全头配置

```javascript
// 使用helmet中间件
const helmet = require('helmet');
app.use(helmet());

// 或手动设置
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    next();
});
```

---

## Express审计清单

```
输入验证:
- [ ] 检查请求体类型验证
- [ ] 搜索 req.query/req.body/req.params 使用
- [ ] 验证MongoDB查询输入
- [ ] 检查文件路径处理

注入漏洞:
- [ ] 搜索 exec/spawn 调用
- [ ] 搜索 eval/Function 使用
- [ ] 检查SQL/NoSQL查询构建
- [ ] 搜索 _.merge/Object.assign

XSS:
- [ ] 检查模板引擎配置
- [ ] 搜索 <%- (EJS不转义)
- [ ] 搜索 {{{ (Handlebars不转义)
- [ ] 检查res.send/res.json内容

会话安全:
- [ ] 检查session secret强度
- [ ] 验证cookie安全配置
- [ ] 检查JWT实现

安全配置:
- [ ] 检查CORS配置
- [ ] 验证helmet/安全头
- [ ] 检查错误处理 (不泄露栈)
- [ ] 验证HTTPS强制

依赖:
- [ ] 运行 npm audit
- [ ] 检查危险依赖包
- [ ] 验证依赖版本
```

---

## 审计正则

```regex
# 命令注入
exec\s*\(|spawn\s*\(|child_process

# NoSQL注入
findOne\s*\(|find\s*\(|updateOne\s*\(

# 原型污染
\.merge\s*\(|Object\.assign\s*\(|__proto__

# XSS
<%-|{{{

# 路径遍历
sendFile\s*\(|res\.download\s*\(
```

## 最小 PoC 示例
```bash
# 路径遍历
curl "http://localhost:3000/download?file=../../etc/passwd"

# NoSQL 注入
curl "http://localhost:3000/user?name[$ne]=1"

# 命令注入
curl "http://localhost:3000/ping?host=google.com;id"
```
