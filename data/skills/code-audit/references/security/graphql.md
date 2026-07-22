# GraphQL 安全检测模块

> GraphQL API安全：未授权字段访问、Introspection暴露、DoS攻击

## 概述 (High Priority)

GraphQL由于其灵活性，存在独特的安全风险：字段级授权缺失、查询复杂度攻击、schema泄露。

---

## 检测类别

### 1. 未授权字段访问

```graphql
# ❌ High: 敏感字段无授权检查
type User {
  id: ID!
  username: String!
  email: String!  # 应该限制访问
  ssn: String!    # Critical: 敏感字段暴露
  salary: Float!  # High: 薪资信息
}

# 攻击: 任何用户可查询
query {
  users {
    id
    ssn      # 越权访问SSN
    salary   # 越权访问薪资
  }
}
```

**检测**:
```bash
# Java (graphql-java)
grep -rn "@GraphQLQuery\|@GraphQLMutation" --include="*.java" -A 10 | \
  grep -v "@PreAuthorize\|checkPermission\|hasRole"

# Schema定义
grep -rn "type User\|type Employee" --include="*.graphql" -A 20 | \
  grep "ssn\|salary\|creditCard\|password"
```

**安全修复**:
```java
// ✓ 字段级授权
@Component
public class UserDataFetcher {
    @PreAuthorize("hasRole('ADMIN') or #userId == authentication.principal.id")
    public String getEmail(User user, @Argument Long userId) {
        return user.getEmail();
    }

    @PreAuthorize("hasRole('HR')")
    public String getSsn(User user) {
        return user.getSsn();
    }
}

// ✓ 或使用DataFetcherDirective
@GraphQLDirective(name = "auth", description = "Requires authentication")
public class AuthDirective implements SchemaDirectiveWiring {
    @Override
    public GraphQLFieldDefinition onField(SchemaDirectiveWiringEnvironment env) {
        GraphQLFieldDefinition field = env.getField();
        return field.transform(builder -> builder
            .dataFetcher(new AuthorizingDataFetcher(field.getDataFetcher()))
        );
    }
}
```

### 2. Introspection未关闭（生产环境）

```graphql
# ❌ Medium: 生产环境Introspection暴露Schema
query {
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}

# 暴露: 所有类型、字段、参数 → 攻击面分析
```

**检测**:
```bash
# Spring Boot GraphQL
grep -rn "spring.graphql.schema.introspection.enabled.*true" application.yml

# graphql-java
grep -rn "GraphQL\.newGraphQL" --include="*.java" -A 10 | \
  grep -v "introspectionEnabled(false)"
```

**安全修复**:
```yaml
# ✓ 生产环境禁用introspection
spring:
  graphql:
    schema:
      introspection:
        enabled: false  # 生产环境

# ✓ 或按环境配置
spring:
  graphql:
    schema:
      introspection:
        enabled: ${GRAPHQL_INTROSPECTION:false}
```

### 3. 批量查询DoS

```graphql
# ❌ High: 无限制批量查询
query {
  users {  # 返回10000个用户
    id
    posts {  # 每个用户10000篇文章
      id
      comments {  # 每篇文章10000条评论
        id
        author {  # 每条评论关联用户
          posts {  # 递归...
            comments { ... }
          }
        }
      }
    }
  }
}

# 导致: 数据库查询爆炸, 内存耗尽, 响应超时
```

**检测**:
```bash
# 检查是否有查询复杂度限制
grep -rn "MaxQueryComplexityInstrumentation\|QueryComplexity" --include="*.java"

# 检查是否有深度限制
grep -rn "MaxQueryDepthInstrumentation" --include="*.java"
```

**安全修复**:
```java
// ✓ 查询复杂度限制
MaxQueryComplexityInstrumentation maxComplexity = new MaxQueryComplexityInstrumentation(200);

// ✓ 查询深度限制
MaxQueryDepthInstrumentation maxDepth = new MaxQueryDepthInstrumentation(10);

GraphQL graphQL = GraphQL.newGraphQL(schema)
    .instrumentation(maxComplexity)
    .instrumentation(maxDepth)
    .build();

// ✓ 分页强制
type Query {
  users(first: Int = 10, after: String): UserConnection!  # 强制分页
}
```

### 4. 深度递归耗尽

```graphql
# ❌ Critical: 循环引用无深度限制
type User {
  friends: [User!]!
}

query {
  user(id: 1) {
    friends {
      friends {
        friends {  # 无限嵌套
          friends { ... }
        }
      }
    }
  }
}
```

**安全修复**:
```java
// ✓ 深度限制
MaxQueryDepthInstrumentation depthLimit = new MaxQueryDepthInstrumentation(5);

// ✓ 或自定义ValidationRule
public class MaxDepthValidationRule extends AbstractRule {
    private final int maxDepth;

    @Override
    public void checkField(ValidationContext context, Field field) {
        int depth = calculateDepth(field);
        if (depth > maxDepth) {
            context.addError(new ValidationError(
                "Query depth exceeds " + maxDepth
            ));
        }
    }
}
```

### 5. IDOR via Nested Query

```graphql
# ❌ High: 嵌套查询绕过顶层鉴权
query {
  publicPost(id: 123) {  # 公开文章，无需鉴权
    author {
      email        # ❌ 但可访问作者私密信息
      phone        # ❌ IDOR: 越权访问
      orders {     # ❌ 访问作者订单
        id
        amount
      }
    }
  }
}
```

**检测**:
```bash
# 检查嵌套类型是否有独立鉴权
grep -rn "type.*{" --include="*.graphql" -A 20 | \
  grep -E "email|phone|address|ssn"
```

**安全修复**:
```java
// ✓ 每个字段独立鉴权
public class UserDataFetcher {
    public String getEmail(User user, DataFetchingEnvironment env) {
        User currentUser = env.getContext().getCurrentUser();

        // 仅自己或管理员可查看email
        if (currentUser.getId().equals(user.getId()) ||
            currentUser.hasRole("ADMIN")) {
            return user.getEmail();
        }
        throw new UnauthorizedException("Cannot access email");
    }
}
```

---

## 综合检测清单

### Critical
- [ ] 敏感字段(SSN/salary/credit card)无授权
- [ ] 深度递归无限制导致DoS

### High
- [ ] 批量查询无复杂度/深度限制
- [ ] IDOR via nested query
- [ ] 生产环境Introspection开启

### Medium
- [ ] 字段级授权不一致
- [ ] 分页未强制

---

## 最小 PoC 示例
```bash
# Introspection
curl -X POST https://api.example.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'

# 批量 DoS
curl -X POST https://api.example.com/graphql \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"{ users { posts { comments { author { posts { id } } } } } }\"}"
```

---

## False Positive

- ✅ Introspection仅在开发环境开启（需环境判断）
- ✅ 公开API有意暴露Schema (需文档说明)
- ✅ 深度/复杂度限制已配置

---

## 参考

- OWASP GraphQL Security Cheat Sheet
- GraphQL Best Practices: Authorization
- graphql-java Security
