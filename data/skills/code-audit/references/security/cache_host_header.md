# 缓存与 Host Header 安全

> 缓存键污染、Host/X-Forwarded-* 头污染、CDN/反向代理绕过

## 高危攻击面
- 缓存键不包含 Host/协议/鉴权信息 → 共享缓存污染
- 信任客户端 Host/X-Forwarded-Host/X-Forwarded-Proto/X-Forwarded-Port
- 代理/网关重写不一致导致源站与边缘缓存键不一致
- 路径规范化差异（`//`,`/./`,`/../`,`;`）导致同资源不同缓存键
- Hop-by-hop 头被错误缓存（`Connection: keep-alive`、`Proxy-Authorization`）
- CDN 自定义头（如 `X-True-Client-IP`）被伪造

## 检测清单
- [ ] 应用是否直接使用 `Host`/`X-Forwarded-*` 构造绝对 URL、重定向、签名 URL
- [ ] 缓存键是否包含 Host + Path + Query + 协议（避免跨域污染）
- [ ] 代理/网关是否清洗客户端 Host/XFH/XFP/XFF
- [ ] Vary 头是否正确（`Vary: Host, Authorization, Cookie, Origin, Accept-Encoding` 等）
- [ ] 是否缓存含鉴权上下文的响应（Cookie/Authorization/Bearer/Session）
- [ ] 规范化行为一致：网关与应用是否同一规则（编码、大小写、尾斜杠、分号）
- [ ] CDN 边缘与源站是否对不同协议/端口共享缓存
- [ ] 是否禁用缓存内部管理/鉴权接口（`Cache-Control: private, no-store`）

## 危险模式
```nginx
# 信任客户端 Host，易缓存污染
proxy_set_header Host $http_host;   # 客户端可控
proxy_set_header X-Forwarded-Host $http_host;

# 未清洗 XFH/XFP，后端用来做重定向
set $redirect_host $http_x_forwarded_host;
return 302 https://$redirect_host/login;
```

```js
// Node.js/Express - 使用 Host 构造重定向
const redirectUrl = `${req.protocol}://${req.get('host')}/login`; // Host 可被污染
res.redirect(redirectUrl); // 开放重定向 + 缓存键污染
```

```conf
# CDN/代理未设置 Vary
Cache-Control: public, max-age=300
# 缺少: Vary: Authorization, Cookie, Accept-Encoding
```

## 检测命令
```bash
# 查找对 Host/X-Forwarded-* 的使用
rg -n "Host|X-Forwarded-(Host|Proto|Port|For)" --glob "*.{js,ts,java,go,py,rb,php,cs}"

# Nginx/Envoy/Traefik 配置
rg -n "proxy_set_header Host|X-Forwarded-Host|X-Forwarded-Proto|X-Forwarded-Port" --glob "*.{conf,yml,yaml}"
rg -n "set_real_ip_from|real_ip_header|trustProxy" --glob "*.{conf,yml,yaml}"

# 缓存控制/Vary
rg -n "Cache-Control|Vary" --glob "*.{conf,nginx,js,ts,go,py,java,cs,rb,php}"
```

## 安全基线
- 网关/代理强制重写：`Host` 设为上游固定域名；清洗客户端 XFH/XFP/XFF
- 应用使用受信头：在网关注入 `X-Forwarded-Host-Safe`，后端只读该头
- 设置正确 Vary：`Vary: Host, Authorization, Cookie, Origin, Accept-Encoding`
- 鉴权页面/用户态响应：`Cache-Control: private, no-store`
- 规范化一致：禁用分号路由、双斜杠合并；对路径做统一 canonical
- CDN：隔离 HTTP/HTTPS/端口的缓存键，关闭匿名对管理路径的缓存
- Web Cache Deception：对静态路径/动态路径分离，禁止将敏感响应缓存到静态后缀
- ESI/边缘注入：关闭不需要的 ESI；对 Edge-Side-Includes 做源站过滤

## 验证步骤
- 构造不同 Host/XFH 访问同一路径，观察是否返回混入其他租户/域的内容
- 带 Cookie/Bearer 的请求命中公共缓存？若命中则为高危
- 试探 `//path`, `/./path`, `/path;param` 是否与 `/path` 产生不同缓存键
- 通过 CDN/XFH 注入外部域名，看重定向、绝对 URL、签名 URL 是否可被伪造

## 最小 PoC 示例
```bash
# Host 污染 + 观察响应
curl -H "Host: attacker.com" https://victim/resource -i
curl -H "X-Forwarded-Host: attacker.com" https://victim/resource -i

# 缓存键污染 (带 Cookie/Bearer)
curl -H "Authorization: Bearer TOKEN" https://victim/account --dump-header headers.txt
curl https://victim/account --dump-header headers2.txt

# 路径规范化
curl -I "https://victim//admin"
curl -I "https://victim/admin;%2f"

# Web Cache Deception
curl -I "https://victim/profile.php/.css"
```
