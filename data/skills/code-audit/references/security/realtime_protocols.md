# 实时协议与缺失框架扩展 (WebSocket/gRPC/SSE + .NET/Rails/Rust/Nest/Fastify)

> 双向通道、长连接、流式接口及未覆盖主流框架的高危审计要点

## 核心风险
- 鉴权缺失/只在握手阶段 → 连接建立后越权订阅/推送
- Origin/Host 未校验 → WebSocket 跨站劫持（WS-CSRF）
- 消息级 ACL 缺失 → 订阅任意房间/主题、广播数据泄露
- 输入验证缺失 → JSON 反序列化、protobuf 反序列化 RCE/DoS
- 消息大小/速率限制缺失 → 内存/CPU DoS
- 压缩 + 反射 → CRIME/BREACH 类压缩侧信道
- gRPC reflection/health 公开，Admin service 暴露
- Nest/Fastify/.NET/Rails/Rust 框架的安全中间件未启用

## WebSocket/SSE/gRPC 检测清单
- [ ] 握手鉴权：是否校验 Cookie/Bearer/API Key，并在消息层再次校验资源权限
- [ ] Origin/Host 白名单：`Origin`/`Sec-WebSocket-Protocol`/`Sec-WebSocket-Version` 校验
- [ ] 订阅/发布授权：频道/主题是否与用户/租户绑定；是否可遍历/猜测 ID 订阅
- [ ] 消息验证：长度上限、速率限制、消息签名/重放保护
- [ ] 反序列化：protobuf/JSON 解析是否存在类型多态、任意类加载、或自定义解码器
- [ ] 管理/调试端点：gRPC reflection、/metrics、/health、/debug 是否暴露
- [ ] 压缩：是否启用 `permessage-deflate` 但未隔离敏感数据（考虑禁用或分流）

## 危险模式
```js
// NestJS WebSocket 网关 - 未鉴权、未限流
@WebSocketGateway()
export class ChatGateway {
  @SubscribeMessage('join')
  handleJoin(@MessageBody() data) {
    // data.room 可控，未绑定用户/租户
    this.server.to(data.room).emit('joined', data.user);
  }
}
```

```go
// gRPC 无拦截器，无限制
server := grpc.NewServer() // 未加 auth/interceptor/limits
pb.RegisterAdminService(server, &Admin{}) // 管理接口暴露
```

```ruby
# Rails ActionCable - 未校验用户与 stream
stream_from params[:room] # room 可控，越权订阅
```

## 检测命令
```bash
# WebSocket/SSE 入口
rg -n "WebSocket|ActionCable|SockJS|socketio|socket.io|ServerSentEvent|EventSource" --glob "*.{js,ts,go,rb,py,java,cs,rs}"
rg -n "@SubscribeMessage|@WebSocketGateway|@OnMessage|@ServerEndpoint" --glob "*.{js,ts,java,cs}"

# gRPC
rg -n "grpc\\.NewServer|grpc::ServerBuilder|AddGrpc" --glob "*.{go,cc,cpp,rs,cs,java}"
rg -n "reflection\\.Register|EnableReflection" --glob "*.{go,cc,cpp,rs,cs,java}"

# 限流/大小
rg -n "MaxReceiveMessageSize|MaxSendMessageSize|permessage-deflate|compression" --glob "*.{go,js,ts,java,cs,rs}"
```

## 框架重点审计要点
- **.NET/ASP.NET Core**: `AddAuthentication`/`AddAuthorization` 是否在 SignalR/Minimal APIs 生效；`UseCors` Origin 限制；`MaxHubConnectionCount`、`MaximumReceiveMessageSize`；`IHubFilter` 做权限/审计。
- **Rails/ActionCable**: `identified_by` 用户绑定；`stream_from` 参数是否白名单；Redis 频道命名是否含租户隔离；禁用未使用的 channels。
- **Rust (Actix/axum/Tonic)**: 中间件鉴权是否作用于 WebSocket/stream 路由；`max_frame_size`、`initial_window_size`；unsafe/cgo 等外部绑定是否存在。
- **NestJS**: `@UseGuards` 是否用于 Gateway；`WsThrottlerGuard`/`ThrottlerGuard` 是否启用；`forRoutes({ path: 'events', method: ALL })` 覆盖 SSE。
- **Fastify**: `fastify-websocket`/`@fastify/websocket` 是否做 Origin 校验；`@fastify/rate-limit` 是否应用于 Upgrade/WS；`trustProxy` 配置与 Host/Origin 验证配合。

## 安全基线
- 统一鉴权：握手+消息层双重鉴权；频道/资源与用户/租户绑定
- Origin 白名单：严格比对域名/协议/端口；拒绝空 Origin
- 限制：消息大小、并发连接数、频率；开启 backpressure；必要时禁用压缩
- 隔离：管理/调试接口仅内网；禁用 gRPC reflection/health 对外暴露
- 日志与审计：记录订阅目标、发送方、速率超限、异常关闭
- 配置示例：
  - gRPC: `grpc.max_receive_message_length`, `keepalive_time_ms`, 关闭 reflection
  - SignalR: `MaximumReceiveMessageSize`, `MaximumParallelInvocationsPerClient`
  - SSE: 明确鉴权中间件，禁用敏感事件缓存，限制并发连接

## 验证步骤
- 使用伪造 Origin/Host 进行 WebSocket/SSE 连接，验证是否被拒
- 未带鉴权或替换为低权限 token 是否能订阅/推送敏感频道
- 枚举频道/房间 ID，确认是否存在越权数据泄露
- gRPC reflection 列出服务/方法，尝试调用管理接口或无限制 streaming 造成 DoS

## 最小 PoC 示例
```bash
# WebSocket Origin 伪造
websocat -H="Origin: https://evil.com" wss://victim/ws

# SSE 未鉴权
curl -H "Authorization: Bearer invalid" https://victim/events

# gRPC reflection 列出服务 (python grpcurl 等价)
grpcurl -plaintext victim:50051 list
grpcurl -plaintext victim:50051 describe admin.AdminService
```
