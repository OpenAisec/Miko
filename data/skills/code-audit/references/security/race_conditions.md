# Race Conditions Detection Module

## Overview
Race conditions (竞态条件) occur when multiple concurrent operations access shared state without proper synchronization, leading to duplicate state changes, quota bypasses, financial abuse, and privilege escalation. Every read–modify–write sequence and multi-step workflow must be treated as potentially vulnerable to concurrent access.

## Critical Impact
- **Financial Loss**: Double spend, over-issuance of credits/refunds, duplicate payments
- **Policy Bypass**: Quota violations, single-use token reuse, rate limit evasion
- **Data Integrity**: Negative counters, duplicate records, inconsistent aggregates
- **Privilege Escalation**: Concurrent role updates, permission bypass

## Detection Priority: CRITICAL

---

## Code Pattern Categories

### 1. Read-Modify-Write Without Atomicity

**Vulnerable Patterns:**

```java
// Java - Non-atomic balance update
int balance = getBalance(userId);
if (balance >= amount) {
    setBalance(userId, balance - amount);  // Race window!
}

// Vulnerable counter increment
int count = cache.get(key);
cache.set(key, count + 1);  // Lost updates possible

// Database read-modify-write without row lock
User user = userRepo.findById(id);
user.setBalance(user.getBalance() - amount);
userRepo.save(user);  // SELECT then UPDATE - race window
```

```python
# Python - File-based counter
with open('counter.txt', 'r') as f:
    count = int(f.read())
with open('counter.txt', 'w') as f:
    f.write(str(count + 1))  # Race between read and write

# Redis non-atomic operations
balance = redis.get(f'balance:{user_id}')
if int(balance) >= amount:
    redis.set(f'balance:{user_id}', int(balance) - amount)  # Race!

# Django ORM update without F()
user = User.objects.get(id=user_id)
user.credits -= cost
user.save()  # SELECT then UPDATE
```

```go
// Go - Map access without mutex
count := counterMap[key]
counterMap[key] = count + 1  // Race condition

// Non-atomic file operations
data, _ := ioutil.ReadFile("state.json")
state := parseState(data)
state.Count++
ioutil.WriteFile("state.json", marshal(state), 0644)  // Race window
```

**Safe Alternatives:**
```java
// Atomic database update
@Query("UPDATE User u SET u.balance = u.balance - :amount WHERE u.id = :id AND u.balance >= :amount")
int deductBalance(@Param("id") Long id, @Param("amount") int amount);

// Optimistic locking with version
@Version
private Long version;

// Pessimistic locking
@Lock(LockModeType.PESSIMISTIC_WRITE)
User findByIdForUpdate(Long id);
```

```python
# Django atomic F() expression
from django.db.models import F
User.objects.filter(id=user_id).update(credits=F('credits') - cost)

# Redis atomic operations
redis.decrby(f'balance:{user_id}', amount)
# Or use Lua script for complex atomicity
```

---

### 2. Multi-Step Operations with Gaps

**Vulnerable Patterns:**

```java
// Check-then-act pattern
if (couponService.isValid(code)) {
    // Gap - coupon could be used by another thread
    applyDiscount(code);
    couponService.markUsed(code);  // Duplicate usage possible
}

// Inventory reservation
if (inventory.getStock(productId) > 0) {
    // Race window - stock could go negative
    createOrder(productId);
    inventory.decrementStock(productId);
}

// Multi-phase payment
String authId = paymentGateway.authorize(amount);
// Gap - could be captured multiple times
paymentGateway.capture(authId);
updateUserBalance(authId);
```

```python
# Token consumption
if not token_used_set.contains(token):
    # Gap - token could be reused concurrently
    perform_action()
    token_used_set.add(token)

# Seat reservation
if get_available_seats(event_id) > 0:
    # Race - seats could be overbooked
    create_reservation(user_id, event_id)
    decrement_seats(event_id)
```

**Detection Rules:**
- Look for conditional blocks where state is checked then modified in separate operations
- Identify time gaps between validation and action (check → reserve → commit)
- Flag sequences: `isValid() → use()`, `hasBalance() → deduct()`, `checkStock() → decrement()`

---

### 3. Idempotency Control Weaknesses

**Vulnerable Patterns:**

```java
// Inadequate idempotency key scope
String idempKey = request.getHeader("Idempotency-Key");
if (!processedKeys.contains(idempKey)) {
    // Missing principal/user scope - key reusable across users!
    processPayment();
    processedKeys.add(idempKey);
}

// Cache-before-commit window
@Transactional
public void processOrder(String idempKey) {
    cache.set(idempKey, "processing");  // Written before TX commits
    // If multiple requests hit here concurrently...
    createOrder();
    // TX commits later - multiple orders created
}

// Short TTL idempotency
if (!redis.exists(idempKey) || redis.ttl(idempKey) < 0) {
    // TTL too short - key could be reused after expiry
    processRefund();
    redis.setex(idempKey, 60, "done");  // Only 60 seconds
}
```

```python
# Application-level deduplication
if idempotency_key not in processed_cache:
    send_email(user)  # Side effect occurs
    credit_account(user)  # Side effect occurs
    processed_cache[idempotency_key] = True
    return {"status": "success"}
return processed_cache[idempotency_key]  # Returns cached response only!
# Problem: Side effects happened despite duplicate detection
```

**Detection Signals:**
- Idempotency keys without user/principal scoping
- Cache writes before transaction commits
- TTL shorter than reasonable retry windows (< 24 hours for financial ops)
- Deduplication that returns cached responses but doesn't prevent side effects

---

### 4. Optimistic Concurrency Missing or Weak

**Vulnerable Patterns:**

```java
// No version checking
@Entity
public class Account {
    // Missing @Version annotation!
    private Long id;
    private BigDecimal balance;
}

// Optional version not enforced
public void updateUser(UserDTO dto) {
    User user = repo.findById(dto.getId());
    // dto.version exists but never checked!
    user.setEmail(dto.getEmail());
    repo.save(user);
}

// ETag/If-Match ignored
@PutMapping("/resource/{id}")
public Resource update(@PathVariable Long id,
                       @RequestBody Resource resource,
                       @RequestHeader(value="If-Match", required=false) String etag) {
    // etag parameter exists but never validated!
    return repo.save(resource);
}
```

```python
# Django without select_for_update
user = User.objects.get(id=user_id)
# Concurrent updates will overwrite each other
user.role = 'admin'
user.save()

# Missing version field enforcement
# Model has 'version' field but it's not used in query
User.objects.filter(id=user_id).update(role='admin')  # Bypasses version check
```

**Safe Patterns:**
```java
// JPA optimistic locking
@Version
@Column(name = "version")
private Long version;

// Explicit version check in query
@Query("UPDATE User u SET u.email = :email WHERE u.id = :id AND u.version = :version")
int updateWithVersion(@Param("id") Long id, @Param("email") String email, @Param("version") Long version);
```

---

### 5. Unique Constraint Violations

**Vulnerable Patterns:**

```java
// Existence check outside database
if (!userRepo.existsByEmail(email)) {
    // Race window - duplicate users possible
    User user = new User(email);
    userRepo.save(user);  // Could fail with constraint violation
}

// Upsert without proper conflict handling
User user = userRepo.findByEmail(email);
if (user == null) {
    user = new User(email);
} else {
    user.setLastLogin(now());
}
repo.save(user);  // Race - duplicate inserts possible
```

```python
# Check-then-create pattern
if not User.objects.filter(email=email).exists():
    # Race window
    User.objects.create(email=email)  # IntegrityError possible under concurrency

# Missing unique constraint
class Coupon(models.Model):
    code = models.CharField(max_length=50)  # No unique=True!
    used = models.BooleanField(default=False)
```

**Safe Patterns:**
```python
# get_or_create with unique constraint
user, created = User.objects.get_or_create(
    email=email,
    defaults={'name': name}
)

# Unique constraint in model
class Coupon(models.Model):
    code = models.CharField(max_length=50, unique=True)
```

---

### 6. Cross-Service Race Conditions

**Vulnerable Patterns:**

```java
// Saga without compensation guards
@Transactional
public void createOrder(OrderRequest req) {
    Order order = orderRepo.save(new Order(req));
    // Async event published
    eventBus.publish(new OrderCreatedEvent(order.getId()));
    // If compensation runs before this commits...
}

// Eventual consistency windows
public void transferFunds(Long fromUser, Long toUser, BigDecimal amount) {
    // Service A deducts
    accountServiceA.deduct(fromUser, amount);
    // Network delay / async processing
    // Service B may not see the deduction yet
    accountServiceB.credit(toUser, amount);
    // User could withdraw from B before A's write is visible
}

// At-least-once delivery without idempotent consumers
@RabbitListener(queues = "payment-queue")
public void handlePayment(PaymentMessage msg) {
    // Message could be delivered multiple times
    processPayment(msg.getAmount());  // Duplicate charges!
    sendConfirmationEmail(msg.getUserId());
}
```

**Detection Rules:**
- Async event publishing before transaction commits
- Cross-service calls without idempotency keys
- Message consumers that aren't idempotent
- Sagas/compensations without state machines or locking

---

### 7. Rate Limit & Quota Bypass

**Vulnerable Patterns:**

```java
// Non-atomic counter updates
int currentCount = rateLimitCache.get(userId);
if (currentCount < LIMIT) {
    // Race - counter could be exceeded
    rateLimitCache.set(userId, currentCount + 1);
    processRequest();
}

// Per-connection enforcement
@RateLimiter(permitsPerSecond = 10, scope = SCOPE.CONNECTION)
public Response apiEndpoint() {
    // User can bypass by opening multiple connections
}

// Sharded counter without coordination
int shard = userId % NUM_SHARDS;
int count = shardedCounters[shard].incrementAndGet();
// Other shards' counts not checked - quota can be exceeded
```

```python
# Cache-based rate limit with race
current = cache.get(f'rate:{user_id}') or 0
if current < RATE_LIMIT:
    cache.set(f'rate:{user_id}', current + 1)  # Race window
    process_request()
else:
    raise RateLimitExceeded()
```

**Safe Patterns:**
```java
// Atomic increment with check
long count = redis.incr("ratelimit:" + userId);
if (count > LIMIT) {
    throw new RateLimitException();
}
redis.expire("ratelimit:" + userId, WINDOW_SECONDS);
```

---

## Special Contexts

### GraphQL Concurrent Mutations

```graphql
mutation {
  refund1: processRefund(orderId: 123) { status }
  refund2: processRefund(orderId: 123) { status }
}
```

**Detection:**
- Batch mutations without per-mutation idempotency
- Resolver-level lack of atomicity
- Parallel execution without coordination

### WebSocket Concurrent Messages

```javascript
// Client sends rapid-fire messages
ws.send(JSON.stringify({action: 'buy', itemId: 1}));
ws.send(JSON.stringify({action: 'buy', itemId: 1}));
```

**Detection:**
- Per-connection authorization only (not per-message)
- Message handlers without idempotency keys
- State mutations without synchronization

### File Upload Race

```java
// Multi-part upload finalization
public void completeUpload(String uploadId) {
    List<Part> parts = getUploadedParts(uploadId);
    // Concurrent completeUpload calls can create duplicate files
    String fileKey = mergePartsToFile(parts);
    recordFileInDatabase(fileKey);
}
```

---

## Detection Checklist

### High-Risk Code Patterns
- [ ] Read-modify-write without atomic operations (`SELECT` then `UPDATE`)
- [ ] Check-then-act sequences (balance check → deduct, stock check → reserve)
- [ ] Idempotency keys without user/principal scope
- [ ] Missing `@Version` annotations on entities with concurrent updates
- [ ] Existence checks (`exists()`) before insert operations
- [ ] Cache writes before transaction commits
- [ ] Non-atomic counter increments (Redis `GET` then `SET`)
- [ ] Rate limiting without atomic operations
- [ ] Message/event consumers without idempotency
- [ ] Cross-service workflows without compensation guards

### High-Risk Operations
- [ ] Financial transactions (payments, refunds, credits)
- [ ] Coupon/discount application
- [ ] Single-use token consumption (OTP, magic links, password reset)
- [ ] Inventory/quota management
- [ ] Seat/resource reservation systems
- [ ] Role/permission updates
- [ ] File upload finalization
- [ ] Background job state transitions

### Framework-Specific Indicators

**Spring/JPA:**
- Missing `@Version` on entities
- `@Transactional` without proper isolation level
- No `@Lock(LockModeType.PESSIMISTIC_WRITE)` on concurrent updates
- Custom queries without version checks

**Django:**
- `.save()` without `.select_for_update()`
- Update without `F()` expressions
- Missing `unique=True` on fields that should be unique
- No transaction isolation level set

**Go:**
- Map access without `sync.Mutex`
- File operations without `flock`
- Database operations without `FOR UPDATE`
- Channel operations without proper synchronization

**Node.js:**
- Async operations without proper locking (redlock, etc.)
- MongoDB updates without `$inc` or atomic operators
- Cache operations without atomic primitives

---

## Severity Assessment

**Critical:**
- Financial operations without atomicity (payments, refunds, balance updates)
- Single-use token reuse vulnerabilities
- Quota/rate limit bypass allowing unbounded resource consumption
- Inventory systems allowing negative stock or over-booking

**High:**
- Role/permission race conditions
- Coupon/discount duplicate application
- Data integrity violations (duplicate records, lost updates)
- Cross-service race conditions in critical workflows

**Medium:**
- Non-critical counter race conditions
- Audit log ordering issues
- Cache consistency race conditions
- Non-financial resource allocation races

---

## Remediation Guidance

1. **Use Database Atomicity:**
   - Single `UPDATE` statements with conditions (`WHERE balance >= amount`)
   - Optimistic locking with `@Version`/version fields
   - Pessimistic locking (`SELECT FOR UPDATE`)
   - Unique constraints instead of existence checks

2. **Implement Idempotency:**
   - Scope: `{idempotency-key}:{user-id}:{operation}`
   - Storage: Persistent (database), not cache-only
   - TTL: Long enough for retries (24h+ for financial ops)
   - Enforcement: Before side effects occur

3. **Atomic Operations:**
   - Redis: `INCR`, `DECRBY`, Lua scripts
   - SQL: `UPDATE ... SET x = x + 1`
   - MongoDB: `$inc`, `$set` with atomic operators
   - Application: `AtomicInteger`, `AtomicLong`, synchronized blocks

4. **Proper Locking:**
   - Distributed locks: Redis with fencing tokens, ZooKeeper
   - Database locks: Row-level, table-level as appropriate
   - Application locks: Only for single-instance deployments

5. **Transaction Isolation:**
   - Use `SERIALIZABLE` for critical financial operations
   - Understand isolation level anomalies (phantom reads, etc.)
   - Event publishing after transaction commits

---

## Common False Positives

- **Read-only operations** without state changes
- **Truly idempotent operations** with proper enforcement
- **Serializable transactions** with correct isolation
- **Operations with unique constraints** that would fail on collision
- **Single-instance deployments** with proper in-memory locking (document this assumption!)

---

## Testing Recommendations

When race conditions are suspected, recommend:

1. **Concurrent Request Testing:**
   - Issue N parallel requests with identical inputs
   - Use HTTP/2 multiplexing for tight synchronization
   - Verify state changes are exactly N or 1 (not N*k)

2. **State Verification:**
   - Check for negative counters, duplicate records
   - Verify conservation properties (total balance unchanged in transfers)
   - Audit logs should match actual state changes

3. **Load Testing:**
   - Race windows widen under load
   - Test with realistic database/network latency
   - Verify behavior under retry storms

---

## 最小 PoC 示例
```bash
# 并发扣款/库存
seq 1 50 | xargs -I{} -P50 curl -s "https://api.example.com/purchase?item=1"

# HTTP/2 并发
h2load -n100 -c20 https://api.example.com/checkout

# Redis 原子性缺失
redis-cli INCR account:1:balance &
```

## 配置/修复示例
- 使用分布式锁（Redis Redlock 需注意过期/时钟偏差；优选单租约合理过期 + watchdog）
- 幂等键：写操作优先占位（幂等表/事务唯一约束），响应缓存不要替代幂等控制
- 数据库：使用乐观锁或悲观锁；为扣款/库存等关键表添加唯一约束/版本字段
- 队列消费：开启手动 ack，避免重复消费导致并发副作用

---

## References

- OWASP: Time-of-check Time-of-use (TOCTOU)
- CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
- CWE-366: Race Condition within a Thread
- CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
- Database Isolation Levels: ANSI SQL-92 Standard
- Distributed Systems: Designing Data-Intensive Applications (Martin Kleppmann)
