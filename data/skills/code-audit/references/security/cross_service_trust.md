# 跨服务信任边界安全检测模块

> 微服务架构中的服务间信任边界、内部鉴权、Header伪造风险

## 概述 (High Priority)

微服务架构中，服务间调用常错误地假设"内网可信"，导致严重的权限绕过和数据泄露。

---

## 检测类别

### 1. 内部接口无鉴权

```java
// ❌ High: 内部接口无任何鉴权
@RestController
@RequestMapping("/internal")  // 假设"内网可信"
public class InternalController {
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable Long id) {
        return userService.findById(id);  // 无权限检查，SSRF可访问
    }
}
```

**检测**:
```bash
grep -rn "@RequestMapping.*\"/internal\|/admin\|/private\"" --include="*.java" -A 10 | \
  grep -v "@PreAuthorize\|@RequiresPermissions\|checkPermission"
```

### 2. X-Internal-User / X-User-Id Header伪造

```java
// ❌ Critical: 信任请求头中的用户信息
@GetMapping("/api/profile")
public UserProfile getProfile(HttpServletRequest request) {
    String userId = request.getHeader("X-User-Id");  // 客户端可伪造!
    return profileService.getProfile(userId);  // 越权访问
}

// ❌ 信任X-Internal-User标记
String internal = request.getHeader("X-Internal-User");
if ("true".equals(internal)) {
    return adminData;  // 绕过鉴权
}
```

**检测**:
```bash
grep -rn "getHeader.*X-User-Id\|X-Internal-User\|X-Auth-User\|X-Forwarded-User" --include="*.java" -A 5
```

**安全修复**:
```java
// ✓ 使用JWT或加密签名的Header
String token = request.getHeader("Authorization");
Claims claims = jwtUtil.parseToken(token);  // 验证签名
String userId = claims.getSubject();

// ✓ 或使用mTLS client certificate
X509Certificate cert = (X509Certificate) request.getAttribute("javax.servlet.request.X509Certificate");
String userId = extractUserIdFromCert(cert);
```

### 3. 服务间Token复用

```java
// ❌ High: 用户Token直接用于服务间调用
@Service
public class OrderService {
    public void createOrder(String userToken) {
        // 用户token传递给下游服务
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + userToken);  // Token复用，无scope限制

        restTemplate.exchange("http://payment-service/charge",
                              HttpMethod.POST, new HttpEntity<>(headers), ...);
    }
}
```

**检测**:
```bash
grep -rn "restTemplate\|feignClient" --include="*.java" -A 10 | \
  grep "Authorization.*userToken\|Bearer.*token"
```

**安全修复**:
```java
// ✓ 使用Service Account Token
String serviceToken = tokenService.getServiceAccountToken("order-service");
headers.set("Authorization", "Bearer " + serviceToken);

// ✓ 或使用Token Exchange (RFC 8693)
TokenExchangeRequest exchangeReq = new TokenExchangeRequest()
    .subject Token(userToken)
    .audience("payment-service")
    .scope("payment:create");
String downstreamToken = tokenService.exchange(exchangeReq);
```

### 4. Feign / gRPC 无mTLS

```java
// ❌ High: Feign HTTP调用无mTLS
@FeignClient(name = "user-service", url = "http://user-service:8080")  // HTTP!
public interface UserClient {
    @GetMapping("/users/{id}")
    User getUser(@PathVariable Long id);
}

// ❌ gRPC insecure channel
ManagedChannel channel = ManagedChannelBuilder
    .forAddress("inventory-service", 9090)
    .usePlaintext()  // 无TLS!
    .build();
```

**检测**:
```bash
grep -rn "@FeignClient.*url.*http://" --include="*.java"
grep -rn "\.usePlaintext()" --include="*.java"
grep -rn "ManagedChannelBuilder\.forAddress" --include="*.java" -A 3
```

**安全修复**:
```java
// ✓ Feign with mTLS
@Configuration
public class FeignConfig {
    @Bean
    public Client feignClient() throws Exception {
        SSLContext sslContext = SSLContextBuilder.create()
            .loadTrustMaterial(trustStore, trustStorePassword)
            .loadKeyMaterial(keyStore, keyStorePassword)
            .build();

        return new Client.Default(sslContext.getSocketFactory(),
                                  new DefaultHostnameVerifier());
    }
}

// ✓ gRPC with TLS
ManagedChannel channel = NettyChannelBuilder
    .forAddress("inventory-service", 9443)
    .sslContext(GrpcSslContexts.forClient()
        .trustManager(new File("ca.crt"))
        .keyManager(new File("client.crt"), new File("client.key"))
        .build())
    .build();
```

---

## 检测清单

### Critical
- [ ] 信任X-User-Id/X-Internal-User等可伪造Header
- [ ] 内部接口完全无鉴权

### High
- [ ] 服务间HTTP调用无mTLS
- [ ] 用户Token直接复用于服务间调用
- [ ] gRPC usePlaintext()

### Medium
- [ ] 内部接口鉴权弱于外部接口
- [ ] 基于IP白名单的内部鉴权（可绕过）

---

## 最小 PoC 示例
```bash
# 伪造内部鉴权头
curl -H "X-User-Id: 1" -H "X-Internal-User: true" https://api.example.com/internal/admin

# gRPC 明文
grpcurl -plaintext internal.example.com:50051 list
```

---

## False Positive

- ✅ Header由API Gateway设置且下游服务仅内网可达（需网络隔离证明）
- ✅ 开发/测试环境的HTTP调用（需明确标注）
- ✅ 健康检查接口无鉴权（需限制路径如/actuator/health）

---

## 参考

- OWASP: Server-Side Request Forgery
- RFC 8693: OAuth 2.0 Token Exchange
- mTLS Best Practices for Microservices
