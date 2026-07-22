# OAuth/OIDC/SAML + 高级 JWT/JWK 安全

> 认证协议高级绕过、token 混淆、重定向安全、JWK/kid 注入

## 核心风险
- 重定向/回调：`redirect_uri`/`post_logout_redirect_uri` 校验缺失或弱校验 → 开放重定向、code 窃取
- 状态关联：`state`/`nonce` 缺失或可预测 → CSRF/重放/混淆攻击
- PKCE 缺失 → 授权码拦截/重放
- Token 混淆：`aud/iss` 未校验或接受不匹配的 token → 跨客户端/跨资源滥用
- JWT/JWK：`alg=none`、HS/RS 混淆、`kid/jku/jwk` 外部可控导致 SSRF/任意密钥导入
- SAML：签名只验证断言不验证响应、`Recipient`/`Audience` 未校验、`KeyInfo` 可控
- 刷新/设备码：刷新令牌未绑定客户端/设备，设备码轮询无限制 → 暴力/撞库

## 危险模式
```js
// 弱 redirect_uri 校验
if (redirectUri.includes('example.com')) { // 子串匹配可绕过
  return redirectUri;
}

// JWT 未校验 iss/aud/alg
const payload = jwt.verify(token, secret); // 未限定 algorithms

// kid 注入 (HS/RS 混淆)
jwt.verify(token, publicKey, { algorithms: ['HS256','RS256'] });
// 攻击者提供 HS256 + kid=publicKey，可伪造
```

```xml
<!-- SAML 仅验证断言签名 -->
<ds:Signature>...</ds:Signature> <!-- Response 未签名，可包裹攻击断言 -->
```

## 检测清单
- [ ] `redirect_uri`/`post_logout_redirect_uri` 严格白名单，使用精确匹配/前缀匹配并禁止 `@`、`//`、`%0d%0a`
- [ ] `state`/`nonce` 随机且验证回传；响应类型 mix-up 保护（客户端校验 `response_type`/`client_id`）
- [ ] PKCE 强制 (`S256`)，`code_verifier` 长度充分
- [ ] JWT 校验 `alg` 固定、`iss`/`aud`/`exp`/`iat`/`nbf` 必选，禁止 `none`
- [ ] `kid/jku/jwk`：仅允许受信域名/内置 JWK 集；禁止 HTTP；缓存/钉死公钥
- [ ] `jwks_uri`/`discovery` 只信任 https + allowlist；禁用客户端传入的 `jku`
- [ ] SAML：Response 与 Assertion 双签名或至少校验 Response；验证 `Recipient`/`Audience`/`InResponseTo`
- [ ] 刷新令牌绑定客户端/设备，旋转刷新令牌；设备码轮询限频/验证码时效
- [ ] 登出回调白名单；前后端分离场景校验 `origin`
- [ ] SAML 双签名（Response + Assertion）或至少 Response；ACS URL 严格匹配；Issuer/Audience/Recipient 校验
- [ ] 反代/负载均衡：不接受客户端传入的 Host/Proto/Port；前后端一致的 redirect_uri 校验

## 检测命令
```bash
# 查找 redirect_uri/state/nonce
rg -n "redirect_uri|post_logout_redirect_uri|state|nonce" --glob "*.{js,ts,go,py,java,cs,rb,php}"

# JWT 验证配置
rg -n "jwt\\.decode|jwt\\.verify|JwtParser|Jwts\\.parser" --glob "*.{js,ts,java,py,go,cs,rb,php}"
rg -n "HS256|RS256|algorithms" --glob "*.{js,ts,java,py,go,cs,rb,php}"

# JWK/kid/jku
rg -n "jwk|jku|kid" --glob "*.{js,ts,java,py,go,cs,rb,php,yml,yaml,properties}"

# SAML
rg -n "SAML|AssertionConsumerService|Audience|Recipient|InResponseTo" --glob "*.{xml,java,cs,rb,py}"
```

## 安全基线
- 发现文档/配置：检查 OIDC discovery (`.well-known/openid-configuration`) 是否允许外部 jku/jwks_uri
- Token 校验：固定算法；对 `iss/aud/azp` 严格校验；启用 `requireSignedTokens`
- 公钥来源：内置/固定 JWKS；对 `kid` 做 allowlist；禁用 HTTP/内网地址
- 重定向：白名单匹配 + URL 解析后再比对；拒绝任意子域/端口/协议混淆
- 流程保护：PKCE 强制；`state`/`nonce` 存储并对比；限制 response_mode=form_post 以防拦截
- SAML：Response/Assertion 双签名；验证 `Recipient/Audience/InResponseTo/NotBefore/NotOnOrAfter`
- 刷新/设备码：旋转刷新令牌、绑定客户端，设备码轮询限频/验证码失效

## 验证步骤
- 伪造 `redirect_uri=https://attacker.com%2f..%2f@legit.com` 看是否被接受
- 发送无/重复 `state`/`nonce` 的授权码流程，确认是否被拒绝
- JWT 使用 `alg=none` 或 HS256+公钥作为密钥能否通过验证
- 提供外部 `jku` 指向攻击者 JWKS，看服务器是否拉取
- SAML Response 未签名或 `Recipient` 与 ACS 不匹配是否被接受

## 最小 PoC 示例
- kid/jku 注入:
```bash
header='{"alg":"HS256","kid":"attacker","jku":"https://attacker.test/jwks.json"}'
payload='{"sub":"admin","iss":"victim","aud":"api","exp":9999999999}'
token="$(echo -n "$header" | base64 -w0).$(echo -n "$payload" | base64 -w0).sig"
curl -H "Authorization: Bearer $token" https://victim/api/me
```
- redirect_uri 绕过:
```bash
curl -I "https://auth.example.com/authorize?client_id=web&response_type=code&redirect_uri=https://attacker.com%2f%40example.com/cb&state=1"
```

## 配置示例（安全）
```yaml
# OIDC discovery (生产)
issuer: https://idp.example.com
jwks_uri: https://idp.example.com/.well-known/jwks.json
redirect_uris:
  - https://app.example.com/callback
post_logout_redirect_uris:
  - https://app.example.com/logout-complete
require_pkce: true
```

```xml
<!-- SAML: Response + Assertion 签名 -->
<md:IDPSSODescriptor>
  <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                          Location="https://idp.example.com/sso"/>
  <md:KeyDescriptor use="signing">...</md:KeyDescriptor>
</md:IDPSSODescriptor>
```
