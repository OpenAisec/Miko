# Java 内存/原生层风险检测模块

> 内存操作、原生代码、底层API安全风险

## 概述

Java内存和原生层操作绕过了JVM安全管理器，可能导致内存破坏、权限提升、DoS等严重安全问题。

**Medium-High级别风险**:

- sun.misc.Unsafe 直接内存操作
- ByteBuffer Direct Memory 堆外内存泄漏
- GraalVM Native Image 安全边界
- JNA动态库加载

---

## 1. sun.misc.Unsafe 风险

### 危险模式

```java
// ❌ High: Unsafe直接内存操作
import sun.misc.Unsafe;
import java.lang.reflect.Field;

Field f = Unsafe.class.getDeclaredField("theUnsafe");
f.setAccessible(true);
Unsafe unsafe = (Unsafe) f.get(null);

// 危险操作
long address = unsafe.allocateMemory(1024);  // 堆外内存，不被GC管理
unsafe.putLong(address, 0x4141414141414141L);  // 任意内存写入
unsafe.freeMemory(address);  // 忘记释放 → 内存泄漏

// 更危险：修改对象字段绕过访问控制
Object obj = new SecureObject();
Field secretField = SecureObject.class.getDeclaredField("secret");
long offset = unsafe.objectFieldOffset(secretField);
unsafe.putObject(obj, offset, "hacked");  // 绕过private/final
```

### 检测规则

```bash
grep -rn "sun\.misc\.Unsafe\|jdk\.internal\.misc\.Unsafe" --include="*.java" -A 5
grep -rn "\.allocateMemory\|\.freeMemory\|\.putLong\|\.getLong" --include="*.java" -B 5
grep -rn "objectFieldOffset" --include="*.java" -A 3
```

### 安全建议

- ✅ **避免使用Unsafe**，使用Java标准API
- ✅ 如必须使用，限制在可信代码路径
- ✅ 使用 `VarHandle` (Java 9+) 替代Unsafe
- ✅ 正确管理allocateMemory/freeMemory配对

---

## 2. ByteBuffer Direct Memory 泄漏

### 危险模式

```java
// ❌ Medium: Direct ByteBuffer内存泄漏
ByteBuffer buffer = ByteBuffer.allocateDirect(1024 * 1024 * 100);  // 100MB堆外内存
// 使用buffer...
// 忘记显式释放，依赖GC → OOM

// ❌ 循环分配Direct Buffer
for (int i = 0; i < 10000; i++) {
    ByteBuffer buf = ByteBuffer.allocateDirect(1024 * 1024);  // 每次10MB
    process(buf);  // Full GC前耗尽进程内存
}
```

### 检测规则

```bash
grep -rn "ByteBuffer\.allocateDirect" --include="*.java" -A 5
grep -rn "MappedByteBuffer" --include="*.java" -A 3
```

### 安全建议

- ✅ 监控Direct Memory使用 (`-XX:MaxDirectMemorySize`)
- ✅ 复用ByteBuffer对象池
- ✅ 显式调用 `((DirectBuffer)buffer).cleaner().clean()`
- ✅ 使用try-with-resources管理NIO资源

---

## 3. GraalVM Native Image 安全边界

### 风险点

```java
// ❌ Medium: Reflection配置不当暴露内部类
// reflect-config.json
{
  "name": "com.example.InternalService",
  "allDeclaredMethods": true,  // 过度开放
  "allDeclaredFields": true
}

// ❌ JNI配置暴露native方法
// jni-config.json
{
  "name": "com.example.NativeLib",
  "methods": [{"name": "executeCommand"}]  // 危险native方法
}
```

### 检测规则

```bash
grep -rn "allDeclaredMethods.*true\|allDeclaredFields.*true" --include="*-config.json"
grep -A 5 "jni-config.json" . 2>/dev/null
```

### 安全建议

- ✅ 最小化reflection/JNI配置
- ✅ 白名单specific方法而非 `allDeclared*`
- ✅ 审计native-image配置文件

---

## 4. JNA动态库加载

### 危险模式

```java
// ❌ High: 用户控制的library path
import com.sun.jna.Native;

String libPath = request.getParameter("lib");  // 用户输入
Native.load(libPath, MyLibrary.class);  // 加载任意.so/.dll → RCE

// ❌ Medium: 无验证的native方法调用
public interface CLib extends Library {
    int system(String cmd);  // 直接暴露system()
}

CLib clib = Native.load("c", CLib.class);
String cmd = request.getParameter("cmd");
clib.system(cmd);  // 命令注入
```

### 检测规则

```bash
grep -rn "Native\.load\|NativeLibrary\.getInstance" --include="*.java" -A 5
grep -rn "extends Library" --include="*.java" -A 10 | grep "system\|exec"
```

### 安全建议

- ✅ **禁止**用户控制library名称或路径
- ✅ 白名单允许的native库
- ✅ 验证native方法调用参数
- ✅ 限制native方法暴露范围

---

## 综合检测清单

### High风险

- [ ] Unsafe直接内存操作
- [ ] JNA用户控制library加载
- [ ] JNA暴露system/exec native方法

### Medium风险

- [ ] Direct ByteBuffer大量分配未释放
- [ ] GraalVM allDeclared*配置过度开放
- [ ] MappedByteBuffer未正确unmap

---

## 最小 PoC 示例
```bash
# JNA 任意库加载
rg -n "Native\\.load" --glob "*.{java,kt}"

# Unsafe 使用
rg -n "sun\\.misc\\.Unsafe|Unsafe" --glob "*.{java,kt}"

# ByteBuffer 大量分配
rg -n "allocateDirect\\(" --glob "*.{java,kt}"
```

---

## False Positive

- ✅ Unsafe用于性能优化的可信库（如Netty）
- ✅ Direct ByteBuffer在池化管理下
- ✅ JNA加载系统标准库（如libc）且方法安全

---

## 参考

- JEP 193: Variable Handles (Unsafe替代)
- JNA Security Best Practices
- GraalVM Native Image Security Guide
