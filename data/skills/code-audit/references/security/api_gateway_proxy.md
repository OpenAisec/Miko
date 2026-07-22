# API Gateway / 反向代理安全检测模块

> API Gateway、反向代理配置漏洞、路由绕过、Header注入

## 概述 (High Priority)

API Gateway和反向代理常因配置不当成为攻击入口，导致鉴权绕过、内部服务暴露。

---

## 检测类别

### 1. 路由绕过 (/api;/admin)

```nginx
# ❌ Nginx路径规范化绕过
location /admin {
    deny all;
}

# 绕过: /admin;/ 或 /admin../ 或 /%61dmin
```

```yaml
# ❌ Spring Cloud Gateway路径绕过
spring:
  cloud:
    gateway:
      routes:
        - id: admin
          uri: http://admin-service
          predicates:
            - Path=/admin/**  # 绕过: /admin;x/ 或 /./admin/
```

**检测**:
```bash
grep -rn "location.*/(admin|internal|private)" nginx.conf
grep -rn "Path=.*/(admin|internal)" application.yml
```

**安全修复**:
```nginx
# ✓ 精确匹配 + 规范化
location = /admin {
    deny all;
}

location ~ ^/admin/ {
    deny all;
}

# ✓ 添加规范化
merge_slashes off;  # 防止//绕过
```

### 2. Path Normalization绕过 (%2f, %5c)

```java
// ❌ Spring Security配置绕过
http.authorizeRequests()
    .antMatchers("/admin/**").hasRole("ADMIN")
    .antMatchers("/api/**").permitAll();

// 绕过: /api/%2e%2e/admin → /admin (URL decode后)
```

**检测**:
```bash
grep -rn "antMatchers\|regexMatchers" --include="*.java" -A 3
```

**安全修复**:
```java
// ✓ 使用StrictHttpFirewall
@Bean
public HttpFirewall httpFirewall() {
    StrictHttpFirewall firewall = new StrictHttpFirewall();
    firewall.setAllowUrlEncodedSlash(false);  // 禁止%2f
    firewall.setAllowBackSlash(false);  // 禁止\
    firewall.setAllowUrlEncodedPercent(false);  // 禁止%25
    firewall.setAllowSemicolon(false);  // 禁止;
    return firewall;
}
```

### 3. Header覆盖 (X-Original-URI / X-Rewrite-URL)

```nginx
# ❌ 信任客户端Header
location / {
    proxy_pass http://backend;
    proxy_set_header X-Original-URI $request_uri;  # 客户端可伪造
}
```

```java
// ❌ 后端信任X-Original-URI做鉴权
String originalUri = request.getHeader("X-Original-URI");
if (originalUri.startsWith("/admin")) {
    // 鉴权逻辑 - 可绕过!
}
```

**检测**:
```bash
grep -rn "proxy_set_header X-Original-URI\|X-Rewrite-URL" nginx.conf
grep -rn "getHeader.*X-Original-URI\|X-Rewrite-URL" --include="*.java"
```

**安全修复**:
```nginx
# ✓ 清除客户端Header，仅网关设置
proxy_set_header X-Original-URI "";  # 先清除
proxy_set_header X-Forwarded-URI $request_uri;  # 网关设置
```

### 4. 内部鉴权Header信任问题

```nginx
# ❌ 网关设置X-Authenticated-User但客户端可伪造
location /api {
    proxy_set_header X-Authenticated-User $remote_user;  # 可为空
    proxy_pass http://backend;
}
```

**安全修复**:
```nginx
# ✓ 强制鉴权，仅鉴权后设置Header
location /api {
    auth_request /auth;  # 先鉴权
    auth_request_set $user $upstream_http_x_user;
    proxy_set_header X-Authenticated-User $user;
    proxy_pass http://backend;
}
```

### 5. gRPC-Web → HTTP/JSON 转换漏洞

```yaml
# ❌ Envoy gRPC-JSON transcoder配置不当
http_filters:
  - name: envoy.filters.http.grpc_json_transcoder
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.grpc_json_transcoder.v3.GrpcJsonTranscoder
      services:
        - "*"  # 过度开放，暴露所有gRPC方法
      print_options:
        always_print_primitive_fields: true
```

**检测**:
```bash
grep -rn "grpc_json_transcoder" envoy.yaml
grep -rn "services:.*\*" envoy.yaml
```

**安全修复**:
```yaml
# ✓ 白名单specific服务
services:
  - "myapp.UserService"
  - "myapp.OrderService"
```

---

## 综合检测清单

### Critical
- [ ] Path traversal绕过鉴权 (/admin;/ /admin../)
- [ ] 信任客户端X-Original-URI做鉴权

### High
- [ ] URL编码绕过 (%2f %5c)
- [ ] gRPC-JSON transcoder暴露所有方法
- [ ] 网关鉴权Header可被客户端伪造

### Medium
- [ ] 路径规范化配置缺失
- [ ] merge_slashes未关闭

---

## False Positive

- ✅ 内部管理接口仅localhost可达
- ✅ 开发环境临时配置
- ✅ 健康检查路径特殊处理

---

## 最小 PoC 示例
```bash
# 路径绕过 (/admin;/)
curl -I "https://victim/admin;/" -H "X-Original-URI: /admin;/"

# 编码绕过 (%2f)
curl -I "https://victim/api/%2e%2e/admin"

# Header 覆盖
curl -I "https://victim/" -H "X-Original-URI: /admin"
```

---

## 参考

- OWASP: API Gateway Security
- Nginx Security Hardening
- Spring Security StrictHttpFirewall
- Envoy Proxy Security Best Practices
