<!-- Threat Modeling Skill | Version 3.2.0 (20260512a) | https://github.com/fr33d3m0n/threat-modeling | License: BSD-3-Clause -->

# Authentication & Authorization Implementation Patterns

Source: Adapted from auth-implementation-patterns skill

## Overview

This reference provides secure implementation patterns for authentication and authorization
systems, directly applicable to STRIDE threat mitigation.

## STRIDE Mapping

| Pattern Category | Mitigates STRIDE |
|-----------------|------------------|
| JWT Authentication | S (Spoofing) |
| Session Management | S (Spoofing), R (Repudiation) |
| OAuth2/OIDC | S (Spoofing) |
| RBAC/ABAC | E (Elevation of Privilege) |
| Password Security | S (Spoofing), I (Info Disclosure) |
| Rate Limiting | D (Denial of Service) |

---

## 1. JWT Authentication Pattern

**Threat Mitigated**: Spoofing (S)

### Token Structure
```typescript
interface JWTPayload {
    userId: string;
    email: string;
    role: string;
    iat: number;  // Issued at
    exp: number;  // Expiration
}
```

### Secure Implementation
```typescript
// Generate short-lived access token + long-lived refresh token
function generateTokens(userId: string, email: string, role: string) {
    const accessToken = jwt.sign(
        { userId, email, role },
        process.env.JWT_SECRET!,
        { expiresIn: '15m' }  // Short-lived
    );

    const refreshToken = jwt.sign(
        { userId },
        process.env.JWT_REFRESH_SECRET!,
        { expiresIn: '7d' }
    );

    return { accessToken, refreshToken };
}

// Verify with proper error handling
function verifyToken(token: string): JWTPayload {
    try {
        return jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new Error('Token expired');
        }
        if (error instanceof jwt.JsonWebTokenError) {
            throw new Error('Invalid token');
        }
        throw error;
    }
}
```

### Security Checklist
- [ ] Short expiration (15-30 minutes)
- [ ] Separate secrets for access/refresh tokens
- [ ] Store refresh tokens hashed in database
- [ ] Implement token rotation on refresh
- [ ] Revoke all tokens on password change

---

## 2. Role-Based Access Control (RBAC) Pattern

**Threat Mitigated**: Elevation of Privilege (E)

### Role Hierarchy
```typescript
enum Role {
    USER = 'user',
    MODERATOR = 'moderator',
    ADMIN = 'admin',
}

const roleHierarchy: Record<Role, Role[]> = {
    [Role.ADMIN]: [Role.ADMIN, Role.MODERATOR, Role.USER],
    [Role.MODERATOR]: [Role.MODERATOR, Role.USER],
    [Role.USER]: [Role.USER],
};

function hasRole(userRole: Role, requiredRole: Role): boolean {
    return roleHierarchy[userRole].includes(requiredRole);
}
```

### Permission-Based Control
```typescript
enum Permission {
    READ_USERS = 'read:users',
    WRITE_USERS = 'write:users',
    DELETE_USERS = 'delete:users',
}

const rolePermissions: Record<Role, Permission[]> = {
    [Role.USER]: [Permission.READ_USERS],
    [Role.MODERATOR]: [Permission.READ_USERS, Permission.WRITE_USERS],
    [Role.ADMIN]: Object.values(Permission),
};

function requirePermission(...permissions: Permission[]) {
    return (req, res, next) => {
        const hasAllPermissions = permissions.every(permission =>
            hasPermission(req.user.role, permission)
        );
        if (!hasAllPermissions) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
}
```

### Security Checklist
- [ ] Deny by default
- [ ] Check authorization on every request
- [ ] Use middleware for consistent enforcement
- [ ] Log authorization failures

---

## 3. Session Security Pattern

**Threat Mitigated**: Spoofing (S), Repudiation (R)

### Secure Session Configuration
```typescript
app.use(
    session({
        store: new RedisStore({ client: redisClient }),
        secret: process.env.SESSION_SECRET!,
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: process.env.NODE_ENV === 'production',  // HTTPS only
            httpOnly: true,  // No JavaScript access
            maxAge: 24 * 60 * 60 * 1000,  // 24 hours
            sameSite: 'strict',  // CSRF protection
        },
    })
);
```

### Security Checklist
- [ ] httpOnly flag set
- [ ] secure flag in production
- [ ] sameSite='strict' or 'lax'
- [ ] Session stored server-side (Redis)
- [ ] Rotate session ID on privilege change

---

## 4. Password Security Pattern

**Threat Mitigated**: Spoofing (S), Information Disclosure (I)

### Password Validation
```typescript
const passwordSchema = z.string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character');
```

### Secure Hashing (Argon2 preferred)
```typescript
import bcrypt from 'bcrypt';

async function hashPassword(password: string): Promise<string> {
    const saltRounds = 12;  // 2^12 iterations
    return bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);  // Constant-time comparison
}
```

### Security Checklist
- [ ] Use Argon2id (preferred) or bcrypt
- [ ] Cost factor >= 12
- [ ] Check against breached password lists
- [ ] Never store plaintext

---

## 5. Rate Limiting Pattern

**Threat Mitigated**: Denial of Service (D)

### Implementation
```typescript
import rateLimit from 'express-rate-limit';

// Login-specific limiter (stricter)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 5,  // 5 attempts
    message: 'Too many login attempts',
});

// General API limiter
const apiLimiter = rateLimit({
    windowMs: 60 * 1000,  // 1 minute
    max: 100,  // 100 requests
});

app.post('/api/auth/login', loginLimiter, loginHandler);
app.use('/api/', apiLimiter);
```

### Security Checklist
- [ ] Stricter limits on auth endpoints
- [ ] Per-IP and per-user limiting
- [ ] Use Redis for distributed rate limiting
- [ ] Implement progressive backoff

---

## 6. Resource Ownership Pattern

**Threat Mitigated**: Information Disclosure (I), Elevation of Privilege (E)

### Implementation
```typescript
async function requireOwnership(resourceType: 'post' | 'comment') {
    return async (req, res, next) => {
        // Admins bypass ownership check
        if (req.user.role === Role.ADMIN) {
            return next();
        }

        // User-scoped query prevents IDOR
        const resource = await db[resourceType].findOne({
            id: req.params.id,
            userId: req.user.userId  // Scope to current user
        });

        if (!resource) {
            return res.status(404).json({ error: 'Not found' });
        }

        next();
    };
}
```

### Security Checklist
- [ ] Always scope queries to user
- [ ] Use UUIDs instead of sequential IDs
- [ ] Return 404 for unauthorized access (avoid enumeration)
- [ ] Log access attempts
