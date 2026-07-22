# Java 8 / Legacy Stack Code Review Guide

Review guidance for codebases still on **Java 8** (and nearby legacy stacks: Spring Boot 2.x, `javax.*`, Hibernate 5). Do **not** require Java 17/21 features (records, text blocks, virtual threads, `ProblemDetail`, etc.) on these PRs.

> For modern stacks (Java 17/21 + Spring Boot 3), use the [Java Guide](java.md).

## Table of Contents

- [When to Use This Guide](#when-to-use-this-guide)
- [Lambdas & Functional Interfaces](#lambdas--functional-interfaces)
- [Stream API](#stream-api)
- [Optional](#optional)
- [Date/Time API (`java.time`)](#datetime-api-javatime)
- [Concurrency: Thread Pools & CompletableFuture](#concurrency-thread-pools--completablefuture)
- [Spring Boot 2](#spring-boot-2)
- [JPA / Hibernate 5](#jpa--hibernate-5)
- [Exception Handling](#exception-handling)
- [Testing](#testing)
- [Review Checklist](#review-checklist)
- [References](#references)

---

## When to Use This Guide

| Scenario | Load |
|----------|------|
| Java 8 / 11 (no modern syntax), Spring Boot 2.x, `javax.persistence` | **This file** |
| Java 17/21, Spring Boot 3, `jakarta.*`, virtual threads | [java.md](java.md) |
| Migrating Boot 2 → Boot 3 | Use both: this guide for legacy pitfalls, `java.md` for the target |

Confirm `java.version`, Spring Boot version, and `javax` vs `jakarta` package names in `pom.xml` / `build.gradle` before choosing a guide.

---

## Lambdas & Functional Interfaces

### Keep them short; prefer method references

```java
// ❌ Long lambdas are hard to read, test, and debug
users.stream().forEach(u -> {
    // dozens of lines of business logic...
});

// ✅ Extract a method, or use a method reference
users.forEach(this::processUser);
```

### Prefer JDK functional interfaces

```java
// ❌ Unnecessary custom functional interface
@FunctionalInterface
interface UserCallback {
    void accept(User u);
}

// ✅ Use Consumer / Function / Predicate / Supplier / BiFunction, etc.
void process(Consumer<User> callback) { ... }
```

### Captured variables must be effectively final

```java
// ❌ Mutating a captured variable → compile error (or Atomic/array hacks)
int sum = 0;
list.forEach(n -> sum += n); // does not compile

// ✅ Reduce with a stream, or use an explicit mutable accumulator type
int sum = list.stream().mapToInt(Integer::intValue).sum();
```

---

## Stream API

### Do not force Streams for simple loops

```java
// ❌ Side effects only — Stream adds no value
items.stream().forEach(item -> process(item));

// ✅ Plain for-each is clearer
for (Item item : items) {
    process(item);
}
```

### Collect with `Collectors` on Java 8

```java
// ❌ Stream.toList() is Java 16+ — not available on Java 8
list.stream().map(...).toList();

// ✅ Java 8
List<Dto> result = list.stream()
    .map(...)
    .collect(Collectors.toList());
```

Note: `Collectors.toList()` is not guaranteed immutable. For an unmodifiable list, wrap with `Collections.unmodifiableList(...)` or use Guava / `List.copyOf` (the latter needs a newer JDK).

### Two classic `Collectors.toMap` pitfalls

```java
// ❌ Null values → NPE (internally uses Map.merge, which forbids null values)
Map<Long, String> map = users.stream()
    .collect(Collectors.toMap(User::getId, User::getNickname)); // nickname may be null

// ✅ Filter first, or handle nulls explicitly
Map<Long, String> map = users.stream()
    .filter(u -> u.getNickname() != null)
    .collect(Collectors.toMap(User::getId, User::getNickname));

// ❌ Duplicate keys → IllegalStateException
.collect(Collectors.toMap(User::getName, Function.identity()));

// ✅ Provide a merge function
.collect(Collectors.toMap(User::getName, Function.identity(), (a, b) -> a));
```

### Be careful with `parallelStream()`

```java
// ❌ Small collections / I/O / shared mutable state — often slower or unsafe
list.parallelStream().forEach(sharedList::add); // race

// ❌ Side-effecting forEach into a non-concurrent collection
map.entrySet().parallelStream().forEach(e -> result.put(e.getKey(), e.getValue()));

// ✅ Consider only for CPU-bound work, no shared mutable state, and large enough data
// ✅ Collect with toMap / toConcurrentMap — do not forEach into an external Map
Map<K, V> result = list.parallelStream()
    .collect(Collectors.toConcurrentMap(Item::getKey, Item::getValue, (a, b) -> a));
```

Parallel streams use `ForkJoinPool.commonPool()` by default and compete with other parallel / CompletableFuture work in the same process.

### Do not mutate the stream source; avoid nested `forEach`

```java
// ❌ Mutating the source during the pipeline → ConcurrentModificationException
list.stream().peek(list::add).count();

// ❌ Nested forEach is hard to read and hard to short-circuit
a.forEach(x -> b.forEach(y -> ...));

// ✅ Prefer flatMap or ordinary loops for cartesian / join-style logic
```

### Prefer primitive streams to avoid boxing

```java
// ❌ Stream<Integer> boxing overhead
int sum = list.stream().map(Order::getAmount).reduce(0, Integer::sum);

// ✅ IntStream / LongStream / DoubleStream
int sum = list.stream().mapToInt(Order::getAmount).sum();
```

---

## Optional

**Intent:** express possible absence as a **return type**, not as a general null replacement.

```java
// ❌ Optional as field / parameter / collection element (serialization, reflection, API noise)
class User {
    private Optional<String> email;
}
void send(Optional<String> email) { ... }
Optional<List<Order>> findOrders(); // empty list already means "none"

// ✅ Return type only; return empty collections for "none"
public Optional<User> findById(Long id) { ... }
public List<Order> findOrders(Long userId) { ... } // emptyList when none
```

### Do not use `isPresent()` + `get()` as a null check

```java
// ❌ More verbose than a null check, and get() can still blow up
if (userOpt.isPresent()) {
    return userOpt.get().getName();
}
return "Unknown";

// ✅ Functional chain (available on Java 8)
return userOpt.map(User::getName).orElse("Unknown");
```

### `orElse` vs `orElseGet`

```java
// ❌ orElse argument is always evaluated (even when the Optional is present)
return findUser(id).orElse(loadDefaultFromDb()); // always hits DB

// ✅ Expensive defaults → orElseGet
return findUser(id).orElseGet(this::loadDefaultFromDb);

// ✅ Required value (Java 8)
return findUser(id).orElseThrow(() -> new UserNotFoundException(id));
// Note: no-arg orElseThrow() is Java 10+; Java 8 requires a Supplier
```

### `of` vs `ofNullable`; nest with `flatMap`

```java
// ❌ of(null) → immediate NPE
Optional.of(possiblyNull);

// ✅
Optional.ofNullable(possiblyNull);

// ❌ map returning Optional → Optional<Optional<T>>
optional.map(this::findOther); // findOther returns Optional

// ✅
optional.flatMap(this::findOther);
```

Java 8 has **no** `Optional.stream()` / `ifPresentOrElse` / `or` (those are Java 9+). Filtering a collection of Optionals:

```java
list.stream()
    .map(this::findUser)
    .filter(Optional::isPresent)
    .map(Optional::get) // OK after filter; or extract a helper
    .collect(Collectors.toList());
```

---

## Date/Time API (`java.time`)

One of the most common production footguns in legacy systems: keeping `Date` / `Calendar` / `SimpleDateFormat`.

```java
// ❌ SimpleDateFormat is not thread-safe; a shared static instance corrupts state
private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd");

// ✅ DateTimeFormatter is immutable and thread-safe
private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
```

### Pick the right type

| Type | Use for |
|------|---------|
| `Instant` | Machine timestamps, audit, cross-service events (UTC timeline) |
| `LocalDate` | Date only (birthday, business day) |
| `LocalDateTime` | Date-time **without** zone; do not use for "when an event happened" |
| `ZonedDateTime` / `OffsetDateTime` | Human time that needs a zone or offset |

```java
// ❌ LocalDateTime for "order placed at" — ambiguous across zones / DST
private LocalDateTime createdAt = LocalDateTime.now();

// ✅ Instant for event time; convert to a zone only for display
private Instant createdAt = Instant.now();

// ❌ now() depends on the JVM default zone — CI / prod / laptop disagree
LocalDate.now();

// ✅ Explicit ZoneId, or inject Clock for tests
LocalDate.now(ZoneOffset.UTC);
LocalDate.now(clock);
```

### Formatting traps

```java
// ❌ YYYY is week-based year — wrong year near year boundaries
DateTimeFormatter.ofPattern("YYYY-MM-dd");

// ✅ Calendar year uses yyyy
DateTimeFormatter.ofPattern("yyyy-MM-dd");
```

Interop with legacy APIs: `date.toInstant()`, `Date.from(instant)`, `LocalDateTime.ofInstant(instant, zone)`.

---

## Concurrency: Thread Pools & CompletableFuture

Java 8 has **no virtual threads**. I/O-heavy work needs a well-sized pool — not `newCachedThreadPool` or an unbounded queue.

```java
// ❌ Unbounded queue + default rejection — latency explodes or OOM under load
ExecutorService exec = Executors.newFixedThreadPool(8); // unbounded queue

// ❌ Never shut down → thread leak
Executors.newFixedThreadPool(8).submit(task);

// ✅ Bounded queue + explicit rejection policy + lifecycle management
ThreadPoolExecutor exec = new ThreadPoolExecutor(
    8, 16, 60L, TimeUnit.SECONDS,
    new ArrayBlockingQueue<>(500),
    new ThreadPoolExecutor.CallerRunsPolicy());
// On shutdown: shutdown → awaitTermination → shutdownNow
```

### CompletableFuture

```java
// ❌ I/O on the common pool (supplyAsync with no Executor)
CompletableFuture.supplyAsync(() -> restTemplate.getForObject(url, Dto.class));

// ✅ Explicit I/O executor
CompletableFuture.supplyAsync(() -> callRemote(), ioExecutor);

// ❌ thenApply returning a CF → nested CompletableFuture<CompletableFuture<T>>
.thenApply(id -> findAsync(id));

// ✅ Dependent async work → thenCompose
.thenCompose(id -> findAsync(id));

// ❌ get()/join() inside async callbacks — starves the pool or deadlocks
.thenApply(x -> other.join());

// ✅ Combine with allOf / thenCombine; join once at the boundary
```

**Timeouts:** Java 8 has no `orTimeout` / `completeOnTimeout` (Java 9+). Use `get(timeout, unit)`, or a scheduler + `applyToEither` that completes exceptionally.

**Exceptions:** Attach `exceptionally` / `handle` / `whenComplete` at the chain boundary so failures are not swallowed.

```java
// ❌ Shared mutable SimpleDateFormat / HashMap as a cache
private static final SimpleDateFormat SDF = ...;
private final Map<String, String> cache = new HashMap<>(); // concurrent puts

// ✅ ConcurrentHashMap; dates via java.time
private final ConcurrentHashMap<String, String> cache = new ConcurrentHashMap<>();
```

---

## Spring Boot 2

Packages are **`javax.*`**, not `jakarta.*`. Do not require a Jakarta migration unless the PR's goal is upgrading to Boot 3.

### Dependency injection

```java
// ❌ Field @Autowired: hard to test, opaque dependencies
@Autowired
private UserRepository userRepo;

// ✅ Constructor injection (Boot 2: single constructor can omit @Autowired)
private final UserRepository userRepo;

public UserService(UserRepository userRepo) {
    this.userRepo = userRepo;
}
```

### Configuration

```java
// ❌ Hard-coded secrets; @Value scattered everywhere
@Value("${app.payment.api-key}")
private String apiKey;

// ✅ @ConfigurationProperties (Java 8 uses a class, not a record)
@ConfigurationProperties(prefix = "app.payment")
public class PaymentProperties {
    private String apiKey;
    private int timeoutMs;
    // getters / setters
}
```

Register with `@EnableConfigurationProperties`. On Boot **2.2+**, `@ConfigurationPropertiesScan` also works (`@SpringBootApplication` scans the startup class package by default).

### RestTemplate must have timeouts

Default is **infinite wait**. A hung downstream can exhaust Tomcat / worker threads.

```java
// ❌ Bare new RestTemplate() — no timeouts
return new RestTemplate();

// ✅ Boot 2.1+ Duration-based timeouts
@Bean
public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder
        .setConnectTimeout(Duration.ofSeconds(2))
        .setReadTimeout(Duration.ofSeconds(5))
        .build();
}
```

If you customize `ClientHttpRequestFactory` (e.g. Apache HttpClient), set connect / read / connectionRequest timeouts on the factory too — otherwise builder timeouts may be ignored.

### Transaction proxy trap (same on Boot 2/3)

```java
// ❌ Same-class self-call — @Transactional does not apply (proxy not invoked)
public void create(Order o) {
    save(o); // internal call
}
@Transactional
public void save(Order o) { ... }

// ✅ Put the transaction boundary on the public entry point, or split into another bean
@Transactional
public void create(Order o) { saveInternal(o); }
```

`@Transactional` on `private` methods is also ineffective.

---

## JPA / Hibernate 5

Entity annotations come from `javax.persistence.*`.

### N+1

> Cross-language background: [N+1 query guide](cross-cutting/n-plus-one-queries.md)

```java
// ❌ EAGER, or loops that trigger lazy loads
@OneToMany(fetch = FetchType.EAGER)
private List<Order> orders;

for (User u : userRepo.findAll()) {
    u.getOrders().size(); // N queries when lazy
}

// ✅ JOIN FETCH / @EntityGraph; keep LAZY by default
@Query("SELECT u FROM User u JOIN FETCH u.orders")
List<User> findAllWithOrders();
```

### Transactions & read-only

```java
// ❌ Transactions opened in Controllers; or @Transactional on private methods
// ✅ Public Service methods; mark reads readOnly
@Transactional(readOnly = true)
public User get(Long id) { ... }
```

### Entities & Lombok

```java
// ❌ @Data equals/hashCode often pulls in lazy associations
@Entity
@Data
public class User { ... }

// ✅ @Getter/@Setter; equals/hashCode on a stable business key, or null-safe id
// ⚠️ Do not include lazy associations; new unsaved entities all have null id,
//    so id-only equals treats them as unequal (usually acceptable)
@Entity
@Getter
@Setter
public class User {
    @Id
    private Long id;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User)) return false;
        return id != null && id.equals(((User) o).id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
```

### Temporal fields

Hibernate 5 supports `java.time`, but mapping `ZonedDateTime` to a zone-less `TIMESTAMP` normalizes with the JVM zone and drifts across regions. Prefer:

- Store UTC: `Instant` or `OffsetDateTime`
- Set `spring.jpa.properties.hibernate.jdbc.time_zone=UTC` when the team agrees
- Migrate legacy `java.util.Date` fields deliberately; do not add new `Date` / `@Temporal` in new code

---

## Exception Handling

Boot 2 does not treat Spring 6 `ProblemDetail` as a first-class citizen (that is a Boot 3 story). Use a shared `@ControllerAdvice` with clear HTTP statuses.

```java
// ❌ Swallow exceptions, printStackTrace, return null to hide failure
try {
    userService.create(user);
} catch (Exception e) {
    e.printStackTrace();
    return null;
}

// ✅ Domain exceptions + global handler
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(UserNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(new ApiError("USER_NOT_FOUND", e.getMessage()));
    }
}
```

Close resources with try-with-resources (Java 7+). Avoid hand-rolled `finally { close() }` that forgets null checks.

---

## Testing

```java
// ❌ @SpringBootTest for every unit test (slow and brittle)
@SpringBootTest
public class UserServiceTest { ... }

// ✅ Pure unit tests: JUnit 4/5 + Mockito
@RunWith(MockitoJUnitRunner.class) // JUnit 4
// or @ExtendWith(MockitoExtension.class) // JUnit 5
public class UserServiceTest {
    @Mock private UserRepository repo;
    @InjectMocks private UserService service;

    @Test
    public void shouldCreateUser() { ... }
}
```

Inject `Clock` into time-sensitive logic so tests do not depend on `Instant.now()`.

Legacy stacks often use JUnit 4; if JUnit 5 is mixed in, keep one runner style per module.

---

## Review Checklist

### Version & scope
- [ ] Confirmed Java 8 / Boot 2 / `javax.*` — do not demand Java 17+ APIs or `jakarta.*`
- [ ] Do not treat "use records / virtual threads / text blocks" as blocking feedback

### Language features
- [ ] Lambdas stay short; prefer method references and standard functional interfaces
- [ ] Streams used for transform / filter / reduce, not simple side-effect loops
- [ ] Collection uses `Collectors.*` (no `Stream.toList()`)
- [ ] `toMap` handles null values and duplicate keys
- [ ] `parallelStream` is justified and has no shared mutable state
- [ ] Optional is return-type only; no `isPresent`+`get` abuse; expensive defaults use `orElseGet`
- [ ] Dates use `java.time`; no shared `SimpleDateFormat`; correct type (`Instant` vs `LocalDateTime`)
- [ ] Patterns use `yyyy`, not week-based `YYYY` (unless week-year is intentional)

### Concurrency
- [ ] Thread pools are bounded and shut down; I/O does not use `ForkJoinPool.commonPool()`
- [ ] CompletableFuture uses an explicit Executor; `thenCompose` for nested async; timeouts and error handling present
- [ ] Shared state uses concurrent collections; no static mutable `DateFormat`

### Spring Boot 2 / JPA
- [ ] Constructor injection; config via `@ConfigurationProperties`
- [ ] `RestTemplate` (and RequestFactory) has connect/read timeouts
- [ ] `@Transactional` on public entry points — no self-invocation / private-method failures
- [ ] No N+1; entities avoid `@Data`; temporal strategy is explicit (UTC)
- [ ] Packages stay consistently `javax.*` — no javax/jakarta mix

### Quality
- [ ] Exceptions are not swallowed; error responses are centralized
- [ ] try-with-resources for I/O and DB resources
- [ ] Core logic has unit tests; time is injectable via `Clock`

---

## References

- [What to Look for in Java 8 Code (JetBrains)](https://blog.jetbrains.com/upsource/2016/08/03/what-to-look-for-in-java-8-code/)
- [JDK-8148463: Collectors.toMap fails on null values](https://bugs.openjdk.org/browse/JDK-8148463)
- [Oracle Tutorial: Parallelism](https://docs.oracle.com/javase/tutorial/collections/streams/parallelism.html)
- [Baeldung: Migrating to Java 8 Date/Time API](https://www.baeldung.com/migrating-to-java-8-date-time-api)
- [Baeldung: CompletableFuture and ThreadPool](https://www.baeldung.com/java-completablefuture-threadpool)
- [Spring Boot RestTemplate customization](https://docs.spring.io/spring-boot/docs/2.7.x/reference/html/io.html#io.rest-client.resttemplate)
- [Thorben Janssen: Hibernate/JPA Date and Time](https://thorben-janssen.com/hibernate-jpa-date-and-time/)
